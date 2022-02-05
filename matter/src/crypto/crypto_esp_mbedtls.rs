use log::error;

use crate::error::Error;

use super::CryptoKeyPair;

pub struct KeyPair {}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }

    pub fn new_from_components(_pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        error!("This API should never get called");

        Ok(Self {})
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_csr<'a>(&self, _out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn get_public_key(&self, _pub_key: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn derive_secret(self, _peer_pub_key: &[u8], _secret: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn sign_msg(&self, _msg: &[u8], _signature: &mut [u8]) -> Result<usize, Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
    fn verify_msg(&self, _msg: &[u8], _signature: &[u8]) -> Result<(), Error> {
        error!("This API should never get called");
        Err(Error::Invalid)
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    error!("This API should never get called");

    Ok(())
}
