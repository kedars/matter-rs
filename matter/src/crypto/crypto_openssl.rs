use crate::error::Error;

use log::error;
use openssl::asn1::Asn1Type;
use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey;
use openssl::pkey::PKey;
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};

use super::CryptoKeyPair;

pub struct KeyPair {
    key: EcKey<pkey::Private>,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        Ok(Self { key })
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut bn_ctx = BigNumContext::new()?;
        let s = self.key.public_key().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;
        let len = s.len();
        pub_key[..len].copy_from_slice(s.as_slice());
        Ok(len)
    }

    fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        let self_pkey = PKey::from_ec_key(self.key)?;

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, peer_pub_key, &mut ctx)?;
        let peer_key = EcKey::from_public_key(&group, &point)?;
        let peer_pkey = PKey::from_ec_key(peer_key)?;

        let mut deriver = Deriver::new(&self_pkey)?;
        deriver.set_peer(&peer_pkey)?;
        Ok(deriver.derive(secret)?)
    }

    fn get_csr<'a>(&self, out_csr: &'a mut [u8]) -> Result<&'a [u8], Error> {
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
            Ok(a)
        } else {
            Err(Error::NoSpace)
        }
    }

    fn sign_msg(&self, msg: &[u8], signature: &mut [u8]) -> Result<usize, Error> {
        // First get the SHA256 of the message
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(msg)?;
        let msg = h.finish()?;

        if signature.len() < 64 {
            return Err(Error::NoSpace);
        }
        safemem::write_bytes(signature, 0);

        let sig = EcdsaSig::sign(&msg, &self.key)?;
        let r = sig.r().to_vec();
        println!("r: {:x?}", r);
        signature[0..r.len()].copy_from_slice(r.as_slice());
        let s = sig.s().to_vec();
        println!("s: {:x?}", s);
        signature[32..(32 + s.len())].copy_from_slice(s.as_slice());
        println!("Signature: {:x?}", signature);
        Ok(64)
    }
}

const P256_KEY_LEN: usize = 256 / 8;
pub fn pubkey_from_der<'a>(der: &'a [u8], out_key: &mut [u8]) -> Result<(), Error> {
    if out_key.len() != P256_KEY_LEN {
        error!("Insufficient length");
        Err(Error::NoSpace)
    } else {
        let key = X509::from_der(der)?.public_key()?.public_key_to_der()?;
        let len = key.len();
        let out_key = &mut out_key[..len];
        out_key.copy_from_slice(key.as_slice());
        Ok(())
    }
}
