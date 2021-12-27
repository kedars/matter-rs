use crate::error::Error;

use super::crypto;
use super::crypto::CryptoPKI;

use super::crypto_dummy::CryptoPKIDummy;
#[cfg(feature = "crypto_openssl")]
use super::crypto_openssl::CryptoPKIOpenSSL;

#[cfg(feature = "crypto_openssl")]
fn crypto_pki_new() -> Result<Box<dyn CryptoPKI>, Error> {
    Ok(Box::new(CryptoPKIOpenSSL::new()?))
}

/*
Input -> CSR Nonce
 Output ->
    Attestation Signature(64) - Attestation Key
    NOCSRElement

NOCSRElement: struct {
    1: csr
    2: Nonce(32)
    3,4,5: Optional/Vendor
}

csr: Certificate Signing Request
  - signed with Node Private Key
  - 'subjectPublicKey' field of CSR: Node Public Key
  -

Attestation Signature: Sign(nocsr_tbs with Device Attestation Private Key)

nocsr_tbs: NOCSRElement || attestation_challenge (from PASE/CASE)


CSR-Process:
    - Generate new key-pair
    - Generate CSR with PKCS#10

*/
pub struct KeyPair {
    pki: Box<dyn crypto::CryptoPKI>,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            pki: crypto_pki_new()?,
        })
    }

    pub fn dummy() -> Result<Self, Error> {
        Ok(Self {
            pki: Box::new(CryptoPKIDummy::new()?),
        })
    }

    pub fn get_csr(&self, csr: &mut [u8]) -> Result<usize, Error> {
        self.pki.get_csr(csr)
    }
}
