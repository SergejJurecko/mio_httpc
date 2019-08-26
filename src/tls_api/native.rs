use std::fmt;
use std::io;
use std::result;

use super::native_tls;
use crate::tls_api::{HashType, Error, Result, self};

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
use crypto_hash as hashf;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
pub fn hash(algo: HashType, data: &[u8]) -> Vec<u8> {
    match algo {
        HashType::MD5 => {
            hashf::digest(hashf::Algorithm::MD5, data)
        }
        HashType::SHA256 => {
            hashf::digest(hashf::Algorithm::SHA256, data)
        }
        HashType::SHA512 => {
            hashf::digest(hashf::Algorithm::SHA512, data)
        }
        HashType::SHA1 => {
            hashf::digest(hashf::Algorithm::SHA1, data)
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple_hash {
    use super::HashType;
    extern "C" {
        fn CC_MD5(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
        fn CC_SHA1(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
        fn CC_SHA256(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
        fn CC_SHA512(data: *const u8, len: usize, out: *mut u8) -> *mut u8;
    }
    pub fn hash(algo: HashType, data: &[u8]) -> Vec<u8> {
        match algo {
            HashType::MD5 => {
                let mut out = vec![0; 16];
                unsafe { CC_MD5(data.as_ptr(), data.len(), out.as_mut_ptr()); }
                out
            }
            HashType::SHA256 => {
                let mut out = vec![0; 32];
                unsafe { CC_SHA256(data.as_ptr(), data.len(), out.as_mut_ptr()); }
                out
            }
            HashType::SHA512 => {
                let mut out = vec![0; 64];
                unsafe { CC_SHA512(data.as_ptr(), data.len(), out.as_mut_ptr()); }
                out
            }
            HashType::SHA1 => {
                let mut out = vec![0; 20];
                unsafe { CC_SHA1(data.as_ptr(), data.len(), out.as_mut_ptr()); }
                out
            }
        }
    }
}
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub use self::apple_hash::*;

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

        self.0.add_root_certificate(cert);

        Ok(self)
    }

    fn add_pem_certificate(&mut self, cert: &[u8]) -> Result<&mut Self> {
        let cert = native_tls::Certificate::from_pem(cert)?;

        self.0.add_root_certificate(cert);

        Ok(self)
    }

    fn danger_accept_invalid_certs(&mut self) -> Result<&mut Self> {
        self.0
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
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
    
    fn peer_certificate(&self) -> Vec<u8> {
        if let Ok(Some(cert)) = self.0.peer_certificate() {
            if let Ok(der) = cert.to_der() {
                return der;
            }
        }
        Vec::new()
    }

    #[cfg(feature = "native_vendor")]
    fn peer_pubkey(&self) -> Vec<u8> {
        if let Ok(Some(cert)) = self.0.peer_certificate() {
            cert.public_key_info_der().unwrap_or(Vec::new())
        } else {
            Vec::new()
        }
    }
    #[cfg(feature = "native")]
    fn peer_pubkey(&self) -> Vec<u8> {
        Vec::new()
    }

    #[cfg(feature = "native_vendor")]
    fn pubkey_chain(&mut self) -> Result<PubkeyIterator<S>> {
        Ok(PubkeyIterator(self.0.certificate_chain()?))
    }
    #[cfg(feature = "native")]
    fn pubkey_chain(&mut self) -> Result<PubkeyIterator<S>> {
        Err(Error::InvalidPin)
    }
}

#[cfg(feature = "native_vendor")]
pub struct PubkeyIterator<'a,S>(native_tls::ChainIterator<'a,S>);
#[cfg(feature = "native_vendor")]
impl<'a,S> Iterator for PubkeyIterator<'a,S> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(cert) = self.0.next() {
            return Some(cert.public_key_info_der().unwrap_or(Vec::new()));
        }
        None
    }
}
#[cfg(feature = "native")]
pub struct PubkeyIterator<'a, S>(&'a std::marker::PhantomData<S>);
#[cfg(feature = "native")]
impl<'a, S> Iterator for PubkeyIterator<'a, S> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
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

impl<S: io::Read + io::Write + fmt::Debug + Send + Sync + 'static>
    tls_api::MidHandshakeTlsStreamImpl<S> for MidHandshakeTlsStream<S>
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
        native_tls::HandshakeError::WouldBlock(s) => tls_api::HandshakeError::Interrupted(
            tls_api::MidHandshakeTlsStream::new(MidHandshakeTlsStream(Some(s))),
        ),
    }
}

impl tls_api::TlsConnector for TlsConnector {
    type Builder = TlsConnectorBuilder;

    fn builder() -> Result<TlsConnectorBuilder> {
        Ok(TlsConnectorBuilder(native_tls::TlsConnector::builder()))
        // .map(TlsConnectorBuilder)
        // .map_err(From::from)
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
            // .build()?
            .connect(domain, stream)
            .map(|s| tls_api::TlsStream::new(TlsStream(s)))
            .map_err(map_handshake_error)
    }
}

// TlsAcceptor and TlsAcceptorBuilder

impl TlsAcceptorBuilder {
    pub fn from_pkcs12(pkcs12: &[u8], password: &str) -> Result<TlsAcceptorBuilder> {
        let pkcs12 = native_tls::Identity::from_pkcs12(pkcs12, password)?;

        Ok(TlsAcceptorBuilder(native_tls::TlsAcceptor::builder(pkcs12)))
        // .map(TlsAcceptorBuilder)
        // .map_err(From::from)
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
