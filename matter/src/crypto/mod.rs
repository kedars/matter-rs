use crate::error::Error;

// APIs particular to a KeyPair so a KeyPair object can be defined
pub trait CryptoKeyPair {
    fn get_csr<'a>(&self, csr: &'a mut [u8]) -> Result<&'a [u8], Error>;
    fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error>;
    fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error>;
    fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error>;
}

#[cfg(feature = "crypto_mbedtls")]
mod crypto_mbedtls;
#[cfg(feature = "crypto_mbedtls")]
pub use self::crypto_mbedtls::*;

#[cfg(feature = "crypto_openssl")]
mod crypto_openssl;
#[cfg(feature = "crypto_openssl")]
pub use self::crypto_openssl::*;

pub mod crypto_dummy;
