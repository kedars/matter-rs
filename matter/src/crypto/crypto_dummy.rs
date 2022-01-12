use log::error;

use crate::error::Error;

use super::CryptoKeyPair;

pub struct KeyPairDummy {}

impl KeyPairDummy {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }
}

impl CryptoKeyPair for KeyPairDummy {
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn derive_secret(self, _peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
}
