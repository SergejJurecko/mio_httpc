use core_foundation::base::{CFRelease, TCFType};
use core_foundation::data::CFData;
// use core_foundation::string::CFString;
// use core_foundation::dictionary::CFDictionary;
use core_foundation_sys::base::{kCFAllocatorDefault, CFAllocatorRef, CFTypeID};
use core_foundation_sys::data::{CFDataGetBytePtr, CFDataGetLength, CFDataRef};
use core_foundation_sys::dictionary::{CFDictionaryGetValueIfPresent, CFDictionaryRef};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::number::{kCFNumberSInt32Type, CFNumberGetValue};
use core_foundation_sys::string::CFStringRef;
use std::ptr;
// Implemented from:
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
            let certificate =
                SecCertificateCreateWithData(kCFAllocatorDefault, der_data.as_concrete_TypeRef());
            if certificate.is_null() {
                None
            } else {
                Some(SecCertificate::wrap_under_create_rule(certificate))
            }
        }
    }

    pub fn pubkey(&self) -> Vec<u8> {
        unsafe {
            let k = self.copy_public_key_from_certificate();
            // let k = SecCertificateCopyKey(self.0);
            let mut error: CFErrorRef = std::ptr::null_mut();
            let public_key_data = SecKeyCopyExternalRepresentation(k, &mut error);
            if public_key_data == ptr::null_mut() {
                CFRelease(k as _);
                return Vec::new();
            }
            let public_key_attributes = SecKeyCopyAttributes(k);

            let mut public_key_type: *const std::os::raw::c_void = ptr::null();
            CFDictionaryGetValueIfPresent(
                public_key_attributes,
                kSecAttrKeyType as _,
                &mut public_key_type as _,
            );
            let mut public_keysize: *const std::os::raw::c_void = ptr::null();
            CFDictionaryGetValueIfPresent(
                public_key_attributes,
                kSecAttrKeySizeInBits as _,
                &mut public_keysize as *mut *const std::os::raw::c_void,
            );
            CFRelease(public_key_attributes as _);
            let mut public_keysize_val: u32 = 0;
            let public_keysize_val_ptr: *mut u32 = &mut public_keysize_val;
            CFNumberGetValue(
                public_keysize as _,
                kCFNumberSInt32Type,
                public_keysize_val_ptr as _,
            );
            let hdr_bytes = get_asn1_header_bytes(public_key_type as _, public_keysize_val);
            if hdr_bytes.len() == 0 {
                return Vec::new();
            }
            CFRelease(k as _);
            let key_data_len = CFDataGetLength(public_key_data) as usize;
            let key_data_slice = std::slice::from_raw_parts(
                CFDataGetBytePtr(public_key_data) as *const u8,
                key_data_len,
            );
            let mut out = Vec::with_capacity(hdr_bytes.len() + key_data_len);
            out.extend_from_slice(hdr_bytes);
            out.extend_from_slice(key_data_slice);

            CFRelease(public_key_data as _);
            out
        }
    }

    fn copy_public_key_from_certificate(&self) -> SecKeyRef {
        unsafe {
            // Create an X509 trust using the using the certificate
            let mut trust: SecTrustRef = ptr::null_mut();
            let policy: SecPolicyRef = SecPolicyCreateBasicX509();
            SecTrustCreateWithCertificates(self.as_concrete_TypeRef(), policy, &mut trust);

            // Get a public key reference for the certificate from the trust
            let mut result: SecTrustResultType = 0;
            SecTrustEvaluate(trust, &mut result);
            let public_key = SecTrustCopyPublicKey(trust);
            CFRelease(policy as _);
            CFRelease(trust as _);
            public_key
        }
    }
}

fn get_asn1_header_bytes(pkt: CFStringRef, ksz: u32) -> &'static [u8] {
    unsafe {
        if CFStringCompare(pkt, kSecAttrKeyTypeRSA, 0) == 0 && ksz == 2048 {
            return &RSA_2048_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeRSA, 0) == 0 && ksz == 4096 {
            return &RSA_4096_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeECSECPrimeRandom, 0) == 0 && ksz == 256 {
            return &EC_DSA_SECP_256_R1_ASN1_HEADER;
        }
        if CFStringCompare(pkt, kSecAttrKeyTypeECSECPrimeRandom, 0) == 0 && ksz == 384 {
            return &EC_DSA_SECP_384_R1_ASN1_HEADER;
        }
    }
    &[]
}

const RSA_2048_ASN1_HEADER: [u8; 24] = [
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
];

const RSA_4096_ASN1_HEADER: [u8; 24] = [
    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00,
];

const EC_DSA_SECP_256_R1_ASN1_HEADER: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

const EC_DSA_SECP_384_R1_ASN1_HEADER: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

pub enum OpaqueSecCertificateRef {}
pub type SecCertificateRef = *mut OpaqueSecCertificateRef;
pub enum OpaqueSecKeyRef {}
pub type SecKeyRef = *mut OpaqueSecKeyRef;
pub enum OpaqueSecTrustRef {}
pub type SecTrustRef = *mut OpaqueSecTrustRef;
pub enum OpaqueSecPolicyRef {}
pub type SecPolicyRef = *mut OpaqueSecPolicyRef;
pub type SecTrustResultType = u32;

pub type CFStringCompareFlags = u32;
pub type CFComparisonResult = i32;

extern "C" {
    pub static kSecAttrKeyType: CFStringRef;
    pub static kSecAttrKeySizeInBits: CFStringRef;
    pub static kSecAttrKeyTypeRSA: CFStringRef;
    pub static kSecAttrKeyTypeECSECPrimeRandom: CFStringRef;
    fn SecCertificateCreateWithData(
        allocator: CFAllocatorRef,
        data: CFDataRef,
    ) -> SecCertificateRef;

    fn SecCertificateGetTypeID() -> CFTypeID;
    fn SecKeyCopyExternalRepresentation(key: SecKeyRef, err: *mut CFErrorRef) -> CFDataRef;

    // fn SecCertificateCopyKey(certificate: SecCertificateRef) -> SecKeyRef;

    fn SecPolicyCreateBasicX509() -> SecPolicyRef;
    fn SecTrustCreateWithCertificates(c: SecCertificateRef, p: SecPolicyRef, t: *mut SecTrustRef);
    fn SecTrustEvaluate(trust: SecTrustRef, result: *mut SecTrustResultType) -> u32;
    fn SecTrustCopyPublicKey(trust: SecTrustRef) -> SecKeyRef;
    fn SecKeyCopyAttributes(key: SecKeyRef) -> CFDictionaryRef;

    pub fn CFStringCompare(
        theString1: CFStringRef,
        theString2: CFStringRef,
        compareOptions: CFStringCompareFlags,
    ) -> CFComparisonResult;
}
