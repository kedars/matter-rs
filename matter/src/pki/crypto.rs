use crate::error::Error;

pub trait CryptoPKI {
    fn get_csr<'a>(&self, csr: &'a mut [u8]) -> Result<&'a [u8], Error>;
}
