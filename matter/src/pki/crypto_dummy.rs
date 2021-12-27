use log::error;

use crate::error::Error;

use super::crypto::CryptoPKI;

pub struct CryptoPKIDummy {}

impl CryptoPKIDummy {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {})
    }
}

impl CryptoPKI for CryptoPKIDummy {
    fn get_csr(&self, _out_csr: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
}
