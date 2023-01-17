use ring::digest;
use rustls::{self, Certificate};
use std::cell::RefCell;
use std::fmt;
use std::io;
use std::result;
use std::str;
use std::sync::Arc;
use webpki;
use webpki_roots;

use crate::tls_api::{self, Error, HashType, Result};

pub fn hash(algo: HashType, data: &[u8]) -> Vec<u8> {
    let mut hasher = match algo {
        HashType::MD5 => {
            let mut md5 = md5::Context::new();
            md5.consume(data);
            let d = md5.compute();
            return Vec::from(&d.0[..]);
        }
        HashType::SHA256 => digest::Context::new(&digest::SHA256),
        HashType::SHA512 => digest::Context::new(&digest::SHA512),
        HashType::SHA1 => digest::Context::new(&digest::SHA1_FOR_LEGACY_USE_ONLY),
    };
    hasher.update(data);
    Vec::from(hasher.finish().as_ref())
}

// thread_local!(static CLIENT_CFG: RefCell<Arc<rustls::ClientConfig>> = RefCell::new(Arc::new(rustls::ClientConfig::new())));
// thread_local!(static CLIENT_CFG_SEALED: RefCell<bool> = RefCell::new(false));

pub struct TlsConnector(Arc<rustls::ClientConfig>);

// pub struct TlsAcceptorBuilder(rustls::ServerConfig);
// pub struct TlsAcceptor(Arc<rustls::ServerConfig>);

pub struct TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    stream: S,
    session: rustls::ClientConnection,
    // Amount of data buffered in session
    write_skip: usize,
}

// TODO: do not require Sync from TlsStream
unsafe impl<S> Sync for TlsStream<S> where S: io::Read + io::Write + fmt::Debug + Send + 'static {}

enum IntermediateError {
    Io(io::Error),
    Tls(rustls::Error),
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

impl From<rustls::Error> for IntermediateError {
    fn from(err: rustls::Error) -> IntermediateError {
        IntermediateError::Tls(err)
    }
}

// TlsStream

impl<S> TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
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

    fn complete_prior_io(&mut self) -> std::io::Result<()> {
        if self.session.is_handshaking() {
            self.session.complete_io(&mut self.stream)?;
        }

        if self.session.wants_write() {
            self.session.complete_io(&mut self.stream)?;
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

impl<S> fmt::Debug for TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("TlsStream")
            .field("stream", &self.stream)
            .field("session", &"...")
            .finish()
    }
}

impl<S> io::Read for TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        // We call complete_io() in a loop since a single call may read only
        // a partial packet from the underlying transport. A full packet is
        // needed to get more plaintext, which we must do if EOF has not been
        // hit. Otherwise, we will prematurely signal EOF by returning 0. We
        // determine if EOF has actually been hit by checking if 0 bytes were
        // read from the underlying transport.
        while self.session.wants_read() {
            let at_eof = self.session.complete_io(&mut self.stream)?.0 == 0;
            if at_eof {
                if let Ok(io_state) = self.session.process_new_packets() {
                    if at_eof && io_state.plaintext_bytes_to_read() == 0 {
                        return Ok(0);
                    }
                }
                break;
            }
        }

        self.session.reader().read(buf)
    }
}

impl<S> io::Write for TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        let len = self.session.writer().write(buf)?;

        // Try to write the underlying transport here, but don't let
        // any errors mask the fact we've consumed `len` bytes.
        // Callers will learn of permanent errors on the next call.
        let _ = self.session.complete_io(&mut self.stream);

        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.writer().flush()?;
        self.session.write_tls(&mut self.stream)?;
        Ok(())
    }
}

impl<S> tls_api::TlsStreamImpl<S> for TlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
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

    fn peer_certificate(&self) -> Vec<u8> {
        // if let Some(mut certs) = self.session.get_peer_certificates() {
        //     if let Some(last) = certs.pop() {
        //         return Vec::from(last.as_ref());
        //     }
        // }
        Vec::new()
    }

    fn peer_pubkey(&self) -> Vec<u8> {
        Vec::new()
    }
}

// MidHandshakeTlsStream

pub struct MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    stream: Option<TlsStream<S>>,
}

impl<S> tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.stream.take().unwrap().complete_handleshake_mid()
    }
}

impl<S> fmt::Debug for MidHandshakeTlsStream<S>
where
    S: io::Read + io::Write + fmt::Debug + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream")
            .field("stream", &self.stream)
            .finish()
    }
}

#[derive(Default)]
pub struct TlsConnectorBuilder {
    ders: Vec<Vec<u8>>,
    accept_invalid: bool,
}
impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;
    type Underlying = Option<rustls::ClientConfig>;

    // fn underlying_mut(&mut self) -> &mut rustls::ClientConfig {
    //     &mut self.0
    // }

    fn add_der_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        self.ders.push(cert.to_vec());
        Ok(self)
    }

    fn add_pem_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        let mut rd = std::io::BufReader::new(cert);
        let certs = rustls_pemfile::certs(&mut rd).unwrap_or_default();
        for cert in certs.into_iter() {
            if cert.len() > 0 {
                self.add_der_certificate(&cert)?;
            }
        }
        Ok(self)
    }

    fn danger_accept_invalid_certs(&mut self) -> Result<&mut Self> {
        self.accept_invalid = true;

        Ok(self)
    }

    fn build(mut self) -> Result<TlsConnector> {
        let mut root_store = rustls::RootCertStore::empty();
        if self.ders.len() > 0 {
            root_store.add_parsable_certificates(&self.ders);
        }
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut cfg = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        if self.accept_invalid {
            struct NoCertificateVerifier;

            impl rustls::client::ServerCertVerifier for NoCertificateVerifier {
                fn verify_server_cert(
                    &self,
                    end_entity: &Certificate,
                    intermediates: &[Certificate],
                    server_name: &rustls::client::ServerName,
                    scts: &mut dyn Iterator<Item = &[u8]>,
                    ocsp_response: &[u8],
                    now: std::time::SystemTime,
                ) -> result::Result<rustls::client::ServerCertVerified, rustls::Error>
                {
                    Ok(rustls::client::ServerCertVerified::assertion())
                }
            }

            cfg.dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateVerifier));
        }

        let cfg = Arc::new(cfg);
        Ok(TlsConnector(cfg))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder::default())
    }

    fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + 'static,
    {
        use std::convert::TryInto;
        // let cfg = CLIENT_CFG.with(|cfg| (*cfg.borrow()).clone());
        // if let Ok(domain) = webpki::DnsNameRef::try_from_ascii_str(domain) {
        let domain = domain
            .try_into()
            .map_err(|_e| tls_api::HandshakeError::Failure(Error::Other("invalid domain")))?;
        let tls_stream = TlsStream {
            stream,
            session: rustls::ClientConnection::new(self.0.clone(), domain)
                .map_err(|e| tls_api::HandshakeError::Failure(Error::Other("invalid domain")))?,
            write_skip: 0,
        };
        // tls_stream.session.set_buffer_limit(16 * 1024);
        tls_stream.complete_handleshake_mid()
    }
}

// TlsAcceptor and TlsAcceptorBuilder

// impl TlsAcceptorBuilder {
//     pub fn from_certs_and_key(certs: &[&[u8]], key: &[u8]) -> Result<TlsAcceptorBuilder> {
//         let mut config = rustls::ServerConfig::new(rustls::NoClientAuth::new());
//         let certs = certs
//             .into_iter()
//             .map(|c| rustls::Certificate(c.to_vec()))
//             .collect();
//         config.set_single_cert(certs, rustls::PrivateKey(key.to_vec()))?;
//         Ok(TlsAcceptorBuilder(config))
//     }
// }

// impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
//     type Acceptor = TlsAcceptor;

//     type Underlying = rustls::ServerConfig;

//     // fn underlying_mut(&mut self) -> &mut Arc<rustls::ServerConfig> {
//     //     &mut self.0
//     // }

//     fn supports_alpn() -> bool {
//         // TODO: https://github.com/sfackler/rust-openssl/pull/646
//         true
//     }

//     fn set_alpn_protocols(&mut self, protocols: &[&str]) -> Result<()> {
//         let mut v = Vec::new();
//         for p in protocols {
//             v.push(Vec::from(p.as_bytes()));
//         }
//         self.0.alpn_protocols = v;
//         Ok(())
//     }

//     fn build(self) -> Result<TlsAcceptor> {
//         Ok(TlsAcceptor(Arc::new(self.0)))
//     }
// }

// impl tls_api::TlsAcceptor for TlsAcceptor {
//     type Builder = TlsAcceptorBuilder;

//     fn accept<S>(
//         &self,
//         stream: S,
//     ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
//     where
//         S: io::Read + io::Write + fmt::Debug + Send + 'static,
//     {
//         let mut tls_stream = TlsStream {
//             stream: stream,
//             session: rustls::ServerSession::new(&self.0),
//             write_skip: 0,
//         };
//         tls_stream.session.set_buffer_limit(16 * 1024);

//         tls_stream.complete_handleshake_mid()
//     }
// }
