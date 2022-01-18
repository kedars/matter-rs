use std::sync::Arc;

use log::error;
use mbedtls::{
    ecp::EcPoint,
    hash::Md,
    hash::{self, Type},
    pk::{EcGroup, EcGroupId, Pk},
    rng::{CtrDrbg, OsEntropy},
    x509,
};

use super::CryptoKeyPair;
use crate::error::Error;

pub struct KeyPair {
    key: Pk,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        Ok(Self {
            key: Pk::generate_ec(&mut ctr_drbg, EcGroupId::SecP256R1)?,
        })
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
        let tmp_priv = self.key.ec_private()?;
        let mut tmp_key =
            Pk::private_from_ec_components(EcGroup::new(EcGroupId::SecP256R1)?, tmp_priv)?;

        let mut builder = x509::csr::Builder::new();
        builder.key(&mut tmp_key);
        builder.signature_hash(mbedtls::hash::Type::Sha256);
        builder.subject("O=CSR")?;

        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        match builder.write_der(out_csr, &mut ctr_drbg) {
            Ok(Some(a)) => {
                return Ok(a);
            }
            Ok(None) => {
                error!("Error in writing CSR: None received");
                return Err(Error::Invalid);
            }
            Err(e) => {
                error!("Error in writing CSR {}", e);
                return Err(Error::TLSStack);
            }
        }
    }

    fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let public_key = self.key.ec_public()?;
        let group = EcGroup::new(EcGroupId::SecP256R1)?;
        let vec = public_key.to_binary(&group, false)?;

        let len = vec.len();
        pub_key[..len].copy_from_slice(vec.as_slice());
        Ok(len)
    }

    fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        // mbedtls requires a 'mut' key. Instead of making a change in our Trait,
        // we just clone the key this way

        let tmp_key = self.key.ec_private()?;
        let mut tmp_key =
            Pk::private_from_ec_components(EcGroup::new(EcGroupId::SecP256R1)?, tmp_key)?;

        let group = EcGroup::new(EcGroupId::SecP256R1)?;
        let other = EcPoint::from_binary(&group, peer_pub_key)?;
        let other = Pk::public_from_ec_components(group, other)?;

        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;

        let len = tmp_key.agree(&other, secret, &mut ctr_drbg)?;
        Ok(len)
    }

    fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        // mbedtls requires a 'mut' key. Instead of making a change in our Trait,
        // we just clone the key this way
        let tmp_key = self.key.ec_private()?;
        let mut tmp_key =
            Pk::private_from_ec_components(EcGroup::new(EcGroupId::SecP256R1)?, tmp_key)?;
        // First get the SHA256 of the message
        let mut msg_hash = [0_u8; super::SHA256_HASH_LEN_BYTES];
        Md::hash(hash::Type::Sha256, msg, &mut msg_hash)?;
        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;

        tmp_key.sign(hash::Type::Sha256, &msg_hash, signature, &mut ctr_drbg)?;
        convert_asn1_sign_to_r_s(signature)
    }
}

// mbedTLS sign() function directly encodes the signature in ASN1. The lower level function
// is not yet exposed to us through the Rust crate. So here, I am crudely extracting the 'r'
// and 's' values from the ASN1 encoding and writing 'r' and 's' back sequentially as is expected
// per the Matter spec.
fn convert_asn1_sign_to_r_s(signature: &mut [u8]) -> Result<usize, Error> {
    if signature[0] == 0x30 {
        // Type 0x30 ASN1 Sequence
        // Length: Skip
        let mut offset: usize = 2;

        // Type 0x2 is Integer (first integer is r)
        if signature[offset] != 2 {
            return Err(Error::Invalid);
        }
        offset += 1;

        // Length
        let len = signature[offset];
        offset += 1;
        // Sometimes length is more than 32 with a 0 prefix-padded, skip over that
        offset += (len - 32) as usize;

        // Extract the 32 bytes of 'r'
        let mut r = [0_u8; super::BIGNUM_LEN_BYTES];
        r.copy_from_slice(&signature[offset..(offset + 32)]);
        offset += 32;

        // Type 0x2 is Integer (this integer is s)
        if signature[offset] != 2 {
            return Err(Error::Invalid);
        }
        offset += 1;

        // Length
        let len = signature[offset];
        offset += 1;
        // Sometimes length is more than 32 with a 0 prefix-padded, skip over that
        offset += (len - 32) as usize;

        // Extract the 32 bytes of 's'
        let mut s = [0_u8; super::BIGNUM_LEN_BYTES];
        s.copy_from_slice(&signature[offset..(offset + 32)]);

        signature[0..32].copy_from_slice(&r);
        signature[32..64].copy_from_slice(&s);

        Ok(64)
    } else {
        Err(Error::Invalid)
    }
}

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    mbedtls::hash::pbkdf2_hmac(Type::Sha256, pass, salt, iter as u32, key)
        .map_err(|_e| Error::TLSStack)
}
