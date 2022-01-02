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
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
}
