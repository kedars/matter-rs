use crate::error::Error;

pub trait CryptoPKI {
    fn get_csr(&self, csr: &mut [u8]) -> Result<usize, Error>;
}
