use crate::error::Error;

use super::{CryptoKeyPair, KeyPairInner};

use super::crypto_dummy::CryptoPKIDummy;

pub struct KeyPair {
    pki: Box<dyn CryptoKeyPair>,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            pki: Box::new(KeyPairInner::new()?),
        })
    }

    pub fn dummy() -> Result<Self, Error> {
        Ok(Self {
            pki: Box::new(CryptoPKIDummy::new()?),
        })
    }

    pub fn get_csr<'a>(&self, csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        self.pki.get_csr(csr)
    }
}
