use crate::error::Error;

use super::crypto::CryptoPKI;
use openssl::asn1::Asn1Type;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey;
use openssl::pkey::PKey;
use openssl::x509::{X509NameBuilder, X509ReqBuilder};

pub struct CryptoPKIOpenSSL {
    key: EcKey<pkey::Private>,
}

impl CryptoPKIOpenSSL {
    pub fn new() -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        Ok(Self { key })
    }
}

impl CryptoPKI for CryptoPKIOpenSSL {
    fn get_csr(&self, out_csr: &mut [u8]) -> Result<usize, Error> {
        let mut builder = X509ReqBuilder::new()?;
        builder.set_version(0)?;

        let pkey = PKey::from_ec_key(self.key.clone())?;
        builder.set_pubkey(&pkey)?;

        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text_with_type("O", "CSR", Asn1Type::IA5STRING)?;
        let subject_name = name_builder.build();
        builder.set_subject_name(&subject_name)?;

        builder.sign(&pkey, MessageDigest::sha256())?;

        let csr_vec = builder.build().to_der()?;
        let csr = csr_vec.as_slice();
        if csr.len() < out_csr.len() {
            let a = &mut out_csr[0..csr.len()];
            a.copy_from_slice(csr);
            Ok(csr.len())
        } else {
            Err(Error::NoSpace)
        }
    }
}
