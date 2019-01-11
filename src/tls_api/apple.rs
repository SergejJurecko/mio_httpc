use core_foundation::base::{CFRelease, TCFType};
use core_foundation::data::CFData;
use core_foundation_sys::base::{kCFAllocatorDefault, CFAllocatorRef, CFTypeID};
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataRef};
use core_foundation_sys::error::CFErrorRef;

// TODO: (this is unused atm)
// https://github.com/datatheorem/TrustKit/blob/3e26bf672c19a1a857379d1deb05caf1fafdc5e3/TrustKit/Pinning/TSKSPKIHashCache.m
pub fn cert_pubkey(v: Vec<u8>) -> Vec<u8> {
    if let Some(cert) = SecCertificate::from_der(&v) {
        return cert.pubkey();
    }
    Vec::new()
}

declare_TCFType! {
    /// A type representing a certificate.
    SecCertificate, SecCertificateRef
}
impl_TCFType!(SecCertificate, SecCertificateRef, SecCertificateGetTypeID);

impl SecCertificate {
    pub fn from_der(der_data: &[u8]) -> Option<SecCertificate> {
        let der_data = CFData::from_buffer(der_data);
        unsafe {
            let certificate = SecCertificateCreateWithData(
                kCFAllocatorDefault,
                der_data.as_concrete_TypeRef(),
            );
            if certificate.is_null() {
                None
            } else {
                Some(SecCertificate::wrap_under_create_rule(certificate))
            }
        }
    }

    pub fn pubkey(&self) -> Vec<u8> {
        unsafe {
            let k = SecCertificateCopyKey(self.0);
            let mut error: CFErrorRef = std::ptr::null_mut();
            let data_ref = SecKeyCopyExternalRepresentation(k, &mut error);
            let len = CFDataGetLength(data_ref);
            let out = Vec::from(std::slice::from_raw_parts(
                CFDataGetBytePtr(data_ref),
                len as usize,
            ));
            CFRelease(data_ref as _);
            out
        }
    }
}

pub enum OpaqueSecCertificateRef {}
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;
pub enum OpaqueSecKeyRef {}
pub type SecKeyRef = *mut OpaqueSecKeyRef;
extern "C" {
    fn SecCertificateCreateWithData(
        allocator: CFAllocatorRef,
        data: CFDataRef,
    ) -> SecCertificateRef;

    fn SecCertificateGetTypeID() -> CFTypeID;
    fn SecKeyCopyExternalRepresentation(key: SecKeyRef, err: *mut CFErrorRef) -> CFDataRef;

    fn SecCertificateCopyKey(certificate: SecCertificateRef) -> SecKeyRef;
}