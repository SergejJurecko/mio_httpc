use webpki;
use webpki_roots;
use ring::digest;
use std::cell::RefCell;
use std::fmt;
use std::io;
use std::result;
use std::str;
use std::sync::Arc;

use rustls;
use crate::tls_api::{HashType, Error, Result, self, rustls::rustls::Session};


pub fn hash(algo: HashType, data: &[u8]) -> Vec<u8> {
    let mut hasher = match algo {
        HashType::MD5 => {
            let mut md5 = md5::Context::new();
            md5.consume(data);
            let d = md5.compute();
            return Vec::from(&d.0[..]);
        }
        HashType::SHA256 => {
            digest::Context::new(&digest::SHA256)
        }
        HashType::SHA512 => {
            digest::Context::new(&digest::SHA512)
        }
        HashType::SHA1 => {
            digest::Context::new(&digest::SHA1)
        }
    };
    hasher.update(data);
    Vec::from(hasher.finish().as_ref())
}

thread_local!(static CLIENT_CFG: RefCell<Arc<rustls::ClientConfig>> = RefCell::new(Arc::new(rustls::ClientConfig::new())));
thread_local!(static CLIENT_CFG_SEALED: RefCell<bool> = RefCell::new(false));

pub struct TlsConnectorBuilder(Option<rustls::ClientConfig>);
pub struct TlsConnector(());

pub struct TlsAcceptorBuilder(rustls::ServerConfig);
pub struct TlsAcceptor(Arc<rustls::ServerConfig>);

// pub struct TlsCfg(Arc<rustls::ClientConfig>);
// impl tls_api::TlsCfg for TlsCfg {
// fn new() -> Box<TlsCfg> {
//     Box::new(TlsCfg(rustls::ClientConfig::new()))
// }
// }

pub struct TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    stream: S,
    session: T,
    // Amount of data buffered in session
    write_skip: usize,
}

// TODO: do not require Sync from TlsStream
unsafe impl<S, T> Sync for TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
}

enum IntermediateError {
    Io(io::Error),
    Tls(rustls::TLSError),
}

impl IntermediateError {
    fn into_error(self) -> Error {
        match self {
            IntermediateError::Io(err) => Error::from(err),
            IntermediateError::Tls(err) => Error::from(err),
        }
    }
}

impl From<io::Error> for IntermediateError {
    fn from(err: io::Error) -> IntermediateError {
        IntermediateError::Io(err)
    }
}

impl From<rustls::TLSError> for IntermediateError {
    fn from(err: rustls::TLSError) -> IntermediateError {
        IntermediateError::Tls(err)
    }
}

// TlsStream

impl<S, T> TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn complete_handshake(&mut self) -> result::Result<(), IntermediateError> {
        while self.session.is_handshaking() {
            // TODO: https://github.com/ctz/rustls/issues/77
            while self.session.is_handshaking() && self.session.wants_write() {
                self.session.write_tls(&mut self.stream)?;
            }
            if self.session.is_handshaking() && self.session.wants_read() {
                let r = self.session.read_tls(&mut self.stream)?;
                if r == 0 {
                    return Err(IntermediateError::Io(::std::io::Error::new(
                        ::std::io::ErrorKind::UnexpectedEof,
                        ::std::io::Error::new(::std::io::ErrorKind::Other, "closed mid handshake"),
                    )));
                }
                self.session.process_new_packets()?;
            }
        }
        Ok(())
    }

    fn complete_handleshake_mid(
        mut self,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        match self.complete_handshake() {
            Ok(_) => Ok(tls_api::TlsStream::new(self)),
            Err(IntermediateError::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                let mid_handshake = tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream {
                    stream: Some(self),
                });
                Err(tls_api::HandshakeError::Interrupted(mid_handshake))
            }
            Err(e) => Err(tls_api::HandshakeError::Failure(e.into_error())),
        }
    }
}

impl<S, T> fmt::Debug for TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .field("session", &"...")
            .finish()
    }
}

impl<S, T> io::Read for TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let r = self.session.read(buf)?;
        if r > 0 {
            return Ok(r);
        }

        loop {
            self.session.read_tls(&mut self.stream)?;
            self.session
                .process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            match self.session.read(buf) {
                Ok(0) => {
                    // No plaintext available yet.
                    continue;
                }
                rc @ _ => {
                    return rc;
                }
            };
        }
    }
}

impl<S, T> io::Write for TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut rd_offset = self.write_skip;
        let mut nsent = 0;
        loop {
            let wrote = if rd_offset < buf.len() {
                self.session.write(&buf[rd_offset..])?
            } else {
                0
            };
            self.write_skip += wrote;
            rd_offset += wrote;
            if self.write_skip > 0 {
                loop {
                    match self.session.write_tls(&mut self.stream) {
                        Ok(0) => {
                            return Ok(0);
                        }
                        Ok(n) => {
                            // we can not rely on returned bytes, as TLS adds its own data
                            if !self.session.wants_write() {
                                nsent += self.write_skip;
                                self.write_skip = 0;
                            }
                            break;
                        }
                        Err(e) => {
                            if e.kind() == ::std::io::ErrorKind::Interrupted {
                                continue;
                            } else if e.kind() == ::std::io::ErrorKind::WouldBlock {
                                if nsent == 0 {
                                    return Err(e);
                                } else {
                                    return Ok(nsent);
                                }
                            }
                            return Err(e);
                        }
                    }
                }
            } else {
                break;
            }
        }
        Ok(nsent)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        self.session.write_tls(&mut self.stream)?;
        Ok(())
    }
}

impl<S, T> tls_api::TlsStreamImpl<S> for TlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn shutdown(&mut self) -> io::Result<()> {
        // TODO: do something
        Ok(())
    }

    fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    fn get_ref(&self) -> &S {
        &self.stream
    }

    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        self.session
            .get_alpn_protocol()
            .map(|s| Vec::from(s))
    }

    fn peer_certificate(&self) -> Vec<u8> {
        if let Some(mut certs) = self.session.get_peer_certificates() {
            if let Some(last) = certs.pop() {
                return Vec::from(last.as_ref());
            }
        }
        Vec::new()
    }

    fn peer_pubkey(&self) -> Vec<u8> {
        Vec::new()
    }
}

// MidHandshakeTlsStream

pub struct MidHandshakeTlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    stream: Option<TlsStream<S, T>>,
}

impl<S, T> tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.stream.take().unwrap().complete_handleshake_mid()
    }
}

impl<T, S> fmt::Debug for MidHandshakeTlsStream<S, T>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
    T: rustls::Session + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream")
            .field("stream", &self.stream)
            .finish()
    }
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;
    type Underlying = Option<rustls::ClientConfig>;

    // fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
    //     &mut self.0
    // }

    fn add_der_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        if let Some(ref mut cfg) = self.0 {
            let mut certvec = Vec::with_capacity(cert.len());
            certvec.extend(cert.iter());
            let cert = rustls::Certificate(certvec);
            cfg.root_store.add(&cert).unwrap();
        }
        Ok(self)
    }

    fn add_pem_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        if let Some(ref mut cfg) = self.0 {
            let mut rd = ::std::io::BufReader::new(cert);
            if cfg.root_store.add_pem_file(&mut rd).is_err() {
                return Err(Error::Other("pem file invalid"));
            }
        }
        Ok(self)
    }

    fn supports_alpn() -> bool {
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&str]) -> Result<()> {
        if let Some(ref mut cfg) = self.0 {
            let mut v = Vec::new();
            for p in protocols {
                v.push(Vec::from(p.as_bytes()));
            }
            cfg.alpn_protocols = v;
        }

        Ok(())
    }

    fn danger_accept_invalid_certs(&mut self) -> Result<&mut Self> {
        struct NoCertificateVerifier;

        impl rustls::ServerCertVerifier for NoCertificateVerifier {
            fn verify_server_cert(
                &self,
                _roots: &rustls::RootCertStore,
                _presented_certs: &[rustls::Certificate],
                _dns_name: webpki::DNSNameRef,
                _ocsp_response: &[u8],
            ) -> result::Result<rustls::ServerCertVerified, rustls::TLSError> {
                Ok(rustls::ServerCertVerified::assertion())
            }
        }
        if let Some(ref mut cfg) = self.0 {
            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerifier));
        }

        Ok(self)
    }

    fn build(mut self) -> Result<TlsConnector> {
        if let Some(mut cfg) = self.0.take() {
            cfg.root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
            CLIENT_CFG_SEALED.with(|f| {
                (*f.borrow_mut()) = true;
            });
            CLIENT_CFG.with(|ccfg| (*ccfg.borrow_mut()) = Arc::new(cfg));
        }

        Ok(TlsConnector(()))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        if CLIENT_CFG_SEALED.with(|f| *f.borrow()) {
            Ok(TlsConnectorBuilder(None))
        } else {
            Ok(TlsConnectorBuilder(Some(rustls::ClientConfig::new())))
        }
    }

    fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + 'static,
    {
        let cfg = CLIENT_CFG.with(|cfg| (*cfg.borrow()).clone());
        if let Ok(domain) = webpki::DNSNameRef::try_from_ascii_str(domain) {
            let mut tls_stream = TlsStream {
                stream,
                session: rustls::ClientSession::new(&cfg, domain),
                write_skip: 0,
            };
            tls_stream.session.set_buffer_limit(16 * 1024);

            return tls_stream.complete_handleshake_mid();
        }
        Err(tls_api::HandshakeError::Failure(Error::Other(
            "invalid domain",
        )))
    }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_certs_and_key(certs: &[&[u8]], key: &[u8]) -> Result<TlsAcceptorBuilder> {
        let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        let certs = certs
            .into_iter()
            .map(|c| rustls::Certificate(c.to_vec()))
            .collect();
        config.set_single_cert(certs, rustls::PrivateKey(key.to_vec()))?;
        Ok(TlsAcceptorBuilder(config))
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = rustls::ServerConfig;

    // fn underlying_mut(&mut self) -> &mut Arc<rustls::ServerConfig> {
    //     &mut self.0
    // }

    fn supports_alpn() -> bool {
        // TODO: https://github.com/sfackler/rust-openssl/pull/646
        true
    }

    fn set_alpn_protocols(&mut self, protocols: &[&str]) -> Result<()> {
        let mut v = Vec::new();
        for p in protocols {
            v.push(Vec::from(p.as_bytes()));
        }
        self.0.alpn_protocols = v;
        Ok(())
    }

    fn build(self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor(Arc::new(self.0)))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<S>(
        &self,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + 'static,
    {
        let mut tls_stream = TlsStream {
            stream: stream,
            session: rustls::ServerSession::new(&self.0),
            write_skip: 0,
        };
        tls_stream.session.set_buffer_limit(16 * 1024);

        tls_stream.complete_handleshake_mid()
    }
}
