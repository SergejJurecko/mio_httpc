use std::fmt;
use std::io;
use std::result;

use crate::tls_api;
use crate::tls_api::{Error, Result};

pub struct TlsConnectorBuilder;
pub struct TlsConnector;

pub struct TlsAcceptorBuilder;
pub struct TlsAcceptor;

pub struct PubkeyIterator<'a, S>(&'a std::marker::PhantomData<S>);
impl<'a, S> Iterator for PubkeyIterator<'a, S> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// Make use of the TLS implementation's crypto hashing functions.
/// Not picking any TLS implementation as a feature means hash will not work also
/// and will always return an empty vec.
pub fn hash(_algo: tls_api::HashType, _data: &[u8]) -> Vec<u8> {
    Vec::new()
}

impl tls_api::TlsConnectorBuilder for TlsConnectorBuilder {
    type Connector = TlsConnector;

    type Underlying = ();

    fn supports_alpn() -> bool {
        false
    }

    fn set_alpn_protocols(&mut self, _protocols: &[&str]) -> Result<()> {
        Err(Error::Other("No TLS"))
    }

    fn add_der_certificate(&mut self, _cert: &[u8]) -> Result<&mut Self> {
        Err(Error::Other("No TLS"))
    }

    fn add_pem_certificate(&mut self, _cert: &[u8]) -> Result<&mut Self> {
        Err(Error::Other("No TLS"))
    }

    fn build(self) -> Result<TlsConnector> {
        Err(Error::Other("No TLS"))
    }

    fn danger_accept_invalid_certs(&mut self) -> Result<&mut Self> {
        Err(Error::Other("No TLS"))
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Err(Error::Other("No TLS"))
    }

    fn connect<S>(
        &self,
        _domain: &str,
        _stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    {
        Err(tls_api::HandshakeError::Failure(Error::Other("No TLS")))
    }

    // fn danger_connect_without_providing_domain_for_certificate_verification_and_server_name_indication<
    //     S,
    // >(
    //     &self,
    //     _stream: S,
    // ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    // where
    //     S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    // {
    //     Err(tls_api::HandshakeError::Failure(Error::Other("No TLS")))
    // }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    // pub fn from_pkcs12(_pkcs12: &[u8], _password: &str) -> Result<TlsAcceptorBuilder> {
    //     Err(Error::Other("No TLS"))
    // }
}

impl tls_api::TlsAcceptorBuilder for TlsAcceptorBuilder {
    type Acceptor = TlsAcceptor;

    type Underlying = ();

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
        Err(Error::Other("No TLS"))
    }
}

impl tls_api::TlsAcceptor for TlsAcceptor {
    type Builder = TlsAcceptorBuilder;

    fn accept<S>(
        &self,
        _stream: S,
    ) -> result::Result<tls_api::TlsStream<S>, tls_api::HandshakeError<S>>
    where
        S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static,
    {
        Err(tls_api::HandshakeError::Failure(Error::Other("No TLS")))
    }
}
