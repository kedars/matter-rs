use crate::error::Error;

use log::error;
use openssl::asn1::Asn1Type;
use openssl::bn::{BigNum, BigNumContext};
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint, EcPointRef, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::pkey::{self, Private};
use openssl::x509::{X509NameBuilder, X509ReqBuilder, X509};
use openssl::{pkey, symm};

use super::CryptoKeyPair;

pub enum KeyType {
    Public(EcKey<pkey::Public>),
    Private(EcKey<pkey::Private>),
}
pub struct KeyPair {
    key: KeyType,
}

impl KeyPair {
    pub fn new() -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = EcKey::generate(&group)?;
        Ok(Self {
            key: KeyType::Private(key),
        })
    }

    pub fn new_from_components(pub_key: &[u8], priv_key: &[u8]) -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let priv_key = BigNum::from_slice(priv_key)?;
        let pub_key = EcPoint::from_bytes(&group, pub_key, &mut ctx)?;
        Ok(Self {
            key: KeyType::Private(EcKey::from_private_components(&group, &priv_key, &pub_key)?),
        })
    }

    pub fn new_from_public(pub_key: &[u8]) -> Result<Self, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = BigNumContext::new()?;
        let pub_key = EcPoint::from_bytes(&group, pub_key, &mut ctx)?;

        Ok(Self {
            key: KeyType::Public(EcKey::from_public_key(&group, &pub_key)?),
        })
    }

    fn public_key_point(&self) -> &EcPointRef {
        match &self.key {
            KeyType::Public(k) => k.public_key(),
            KeyType::Private(k) => k.public_key(),
        }
    }

    fn private_key(&self) -> Result<&EcKey<Private>, Error> {
        match &self.key {
            KeyType::Public(_) => Err(Error::Invalid),
            KeyType::Private(k) => Ok(&k),
        }
    }
}

impl CryptoKeyPair for KeyPair {
    fn get_public_key(&self, pub_key: &mut [u8]) -> Result<usize, Error> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut bn_ctx = BigNumContext::new()?;
        let s = self.public_key_point().to_bytes(
            &group,
            PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;
        let len = s.len();
        pub_key[..len].copy_from_slice(s.as_slice());
        Ok(len)
    }

    fn derive_secret(self, peer_pub_key: &[u8], secret: &mut [u8]) -> Result<usize, Error> {
        let self_pkey = PKey::from_ec_key(self.private_key()?.clone())?;

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

        let pkey = PKey::from_ec_key(self.private_key()?.clone())?;
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

        if signature.len() < super::EC_SIGNATURE_LEN_BYTES {
            return Err(Error::NoSpace);
        }
        safemem::write_bytes(signature, 0);

        let sig = EcdsaSig::sign(&msg, self.private_key()?)?;
        let r = sig.r().to_vec();
        signature[0..r.len()].copy_from_slice(r.as_slice());
        let s = sig.s().to_vec();
        signature[32..(32 + s.len())].copy_from_slice(s.as_slice());
        Ok(64)
    }

    fn verify_msg(&self, msg: &[u8], signature: &[u8]) -> Result<(), Error> {
        // First get the SHA256 of the message
        let mut h = Hasher::new(MessageDigest::sha256())?;
        h.update(msg)?;
        let msg = h.finish()?;

        let r = BigNum::from_slice(&signature[0..super::BIGNUM_LEN_BYTES])?;
        let s =
            BigNum::from_slice(&signature[super::BIGNUM_LEN_BYTES..(2 * super::BIGNUM_LEN_BYTES)])?;
        let sig = EcdsaSig::from_private_components(r, s)?;

        let k = match &self.key {
            KeyType::Public(key) => key,
            _ => {
                error!("Not yet supported");
                return Err(Error::Invalid);
            }
        };
        if !sig.verify(&msg, k)? {
            Err(Error::InvalidSignature)
        } else {
            Ok(())
        }
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

pub fn pbkdf2_hmac(pass: &[u8], iter: usize, salt: &[u8], key: &mut [u8]) -> Result<(), Error> {
    openssl::pkcs5::pbkdf2_hmac(pass, salt, iter, MessageDigest::sha256(), key)
        .map_err(|_e| Error::TLSStack)
}

pub fn encrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
    data_len: usize,
) -> Result<usize, Error> {
    let plain_text = &data[..data_len];
    const TAG_LEN: usize = 16;
    let mut tag = [0u8; TAG_LEN];

    let result = symm::encrypt_aead(
        symm::Cipher::aes_128_ccm(),
        key,
        Some(nonce),
        ad,
        plain_text,
        &mut tag,
    )?;
    data[..data_len].copy_from_slice(result.as_slice());
    data[data_len..(data_len + TAG_LEN)].copy_from_slice(&tag);
    Ok(result.len() + TAG_LEN)
}

pub fn decrypt_in_place(
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    data: &mut [u8],
) -> Result<usize, Error> {
    const TAG_LEN: usize = 16;
    let tag_start = data.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&data[tag_start..]);
    let data = &mut data[..tag_start];

    let result = symm::decrypt_aead(
        symm::Cipher::aes_128_ccm(),
        key,
        Some(nonce),
        ad,
        data,
        &tag,
    )?;
    data[..result.len()].copy_from_slice(result.as_slice());
    Ok(result.len())
}
