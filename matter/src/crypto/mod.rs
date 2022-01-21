use crate::error::Error;

pub const SYMM_KEY_LEN_BITS: usize = 128;
pub const SYMM_KEY_LEN_BYTES: usize = SYMM_KEY_LEN_BITS / 8;

pub const AEAD_MIC_LEN_BITS: usize = 128;
pub const AEAD_MIC_LEN_BYTES: usize = AEAD_MIC_LEN_BITS / 8;

pub const AEAD_NONCE_LEN_BYTES: usize = 13;
pub const AEAD_AAD_LEN_BYTES: usize = 8;

pub const SHA256_HASH_LEN_BYTES: usize = 256 / 8;

pub const BIGNUM_LEN_BYTES: usize = 32;
pub const EC_POINT_LEN_BYTES: usize = 65;

pub const ECDH_SHARED_SECRET_LEN_BYTES: usize = 32;

pub const EC_SIGNATURE_LEN_BYTES: usize = 64;

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
