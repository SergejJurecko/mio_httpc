use std::io;
use std::result;
use std::fmt;

use tls_api;
use tls_api::{Error, Result};
use native_tls;

pub struct TlsConnectorBuilder(pub native_tls::TlsConnectorBuilder);
pub struct TlsConnector(pub native_tls::TlsConnector);

pub struct TlsAcceptorBuilder(pub native_tls::TlsAcceptorBuilder);
pub struct TlsAcceptor(pub native_tls::TlsAcceptor);

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = native_tls::TlsConnectorBuilder;

    // fn underlying_mut(&mut self) -> &mut native_tls::TlsConnectorBuilder {
    //     &mut self.0
    // }

    fn supports_alpn() -> bool {
        false
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&str]) -> Result<()> {
        Err(Error::Other("ALPN is not implemented in rust-native-tls"))
    }

    fn add_der_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        let cert = native_tls::Certificate::from_der(cert)?;

        self.0.add_root_certificate(cert)?;

        Ok(self)
    }

    fn add_pem_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        let cert = native_tls::Certificate::from_pem(cert)?;

        self.0.add_root_certificate(cert)?;

        Ok(self)
    }

    fn build(self) -> Result<TlsConnector> {
        self.0.build().map(TlsConnector).map_err(From::from)
    }
}

#[derive(Debug)]
struct TlsStream<S: io::Read + io::Write + fmt::Debug>(native_tls::TlsStream<S>);

impl<S: io::Read + io::Write + fmt::Debug> TlsStream<S> {}

impl<S: io::Read + io::Write + fmt::Debug> io::Read for TlsStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: io::Read + io::Write + fmt::Debug> io::Write for TlsStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl<S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static> tls_api::TlsStreamImpl<S>
    for TlsStream<S>
{
    fn shutdown(&mut self) -> io::Result<()> {
        self.0.shutdown()
    }

    fn get_mut(&mut self) -> &mut S {
        self.0.get_mut()
    }

    fn get_ref(&self) -> &S {
        self.0.get_ref()
    }

    fn get_alpn_protocol(&self) -> Option<Vec<u8>> {
        None
    }
}

struct MidHandshakeTlsStream<S: io::Read + io::Write + 'static>(
    Option<native_tls::MidHandshakeTlsStream<S>>,
);

impl<S: io::Read + io::Write> fmt::Debug for MidHandshakeTlsStream<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MidHandshakeTlsStream").finish()
    }
}

impl<
    S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
> tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S>
{
    fn handshake(&mut self) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>> {
        self.0
            .take()
            .unwrap()
            .handshake()
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}

fn map_handshake_error<S>(e: native_tls::HandshakeError<S>) -> tls_api::HandshakeError<S>
where
    S: io::Read + io::Write + Send + Sync + fmt::Debug + 'static,
{
    match e {
        native_tls::HandshakeError::Failure(e) => tls_api::HandshakeError::Failure(From::from(e)),
        native_tls::HandshakeError::Interrupted(s) => tls_api::HandshakeError::Interrupted(
            tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream(Some(s))),
        ),
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        native_tls::TlsConnector::builder()
            .map(TlsConnectorBuilder)
            .map_err(From::from)
    }

    fn connect<S>(
        &self,
        domain: &str,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    {
        self.0
            .connect(domain, stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }

    fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<
        S,
    >(
        &self,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    {
        self.0.danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication(stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(pkcs12: &[u8], password: &str) -> Result<TlsAcceptorBuilder> {
        let pkcs12 = native_tls::Pkcs12::from_der(pkcs12, password)?;

        native_tls::TlsAcceptor::builder(pkcs12)
            .map(TlsAcceptorBuilder)
            .map_err(From::from)
    }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = native_tls::TlsAcceptorBuilder;

    fn supports_alpn() -> bool {
        false
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&str]) -> Result<()> {
        Err(Error::Other("ALPN is not implemented in rust-native-tls"))
    }

    // fn underlying_mut(&mut self) -> &mut native_tls::TlsAcceptorBuilder {
    //     &mut self.0
    // }

    fn build(self) -> Result<TlsAcceptor> {
        self.0.build().map(TlsAcceptor).map_err(From::from)
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<S>(
        &self,
        stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    {
        self.0
            .accept(stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}
