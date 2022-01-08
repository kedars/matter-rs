use std::sync::Arc;

use log::error;
use mbedtls::{
    pk::{EcGroup, EcGroupId, Pk},
    rng::{CtrDrbg, OsEntropy},
    x509,
};

use super::CryptoKeyPair;
use crate::error::Error;

pub struct KeyPairInner {
    key: Pk,
}

impl KeyPairInner {
    pub fn new() -> Result<Self, Error> {
        let mut ctr_drbg = CtrDrbg::new(Arc::new(OsEntropy::new()), None)?;
        Ok(Self {
            key: Pk::generate_ec(&mut ctr_drbg, EcGroupId::SecP256R1)?,
        })
    }
}

impl CryptoKeyPair for KeyPairInner {
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
}
