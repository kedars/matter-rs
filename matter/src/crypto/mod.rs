use crate::error::Error;

// APIs particular to a KeyPair so a KeyPair object can be defined
pub trait CryptoKeyPair {
    fn get_csr<'a>(&self, csr: &'a mut [u8]) -> Result<&'a [u8], Error>;
}

#[cfg(feature = "crypto_mbedtls")]
mod crypto_mbedtls;
#[cfg(feature = "crypto_mbedtls")]
pub use self::crypto_mbedtls::*;

#[cfg(feature = "crypto_openssl")]
mod crypto_openssl;
#[cfg(feature = "crypto_openssl")]
pub use self::crypto_openssl::*;

mod crypto_dummy;
pub mod pki;
