use crate::{
    error::Error,
    tlv::{self, TLVElement},
    tlv_common::TagType,
};
use num_derive::FromPrimitive;

#[derive(FromPrimitive)]
pub enum CertTags {
    SerialNum = 1,
    SignAlgo = 2,
    Issuer = 3,
    NotBefore = 4,
    NotAfter = 5,
    Subject = 6,
    PubKeyAlgo = 7,
    EcCurveId = 8,
    EcPubKey = 9,
    Extensions = 10,
    Signature = 11,
}

#[derive(FromPrimitive, Debug)]
pub enum EcCurveIdValue {
    Prime256V1 = 1,
}

pub fn get_ec_curve_id(algo: u8) -> Option<EcCurveIdValue> {
    num::FromPrimitive::from_u8(algo)
}

#[derive(FromPrimitive, Debug)]
pub enum PubKeyAlgoValue {
    EcPubKey = 1,
}

pub fn get_pubkey_algo(algo: u8) -> Option<PubKeyAlgoValue> {
    num::FromPrimitive::from_u8(algo)
}

#[derive(FromPrimitive, Debug)]
pub enum SignAlgoValue {
    ECDSAWithSHA256 = 1,
}

pub fn get_sign_algo(algo: u8) -> Option<SignAlgoValue> {
    num::FromPrimitive::from_u8(algo)
}

const KEY_USAGE_DIGITAL_SIGN: u16 = 0x0001;
const KEY_USAGE_NON_REPUDIATION: u16 = 0x0002;
const KEY_USAGE_KEY_ENCIPHERMENT: u16 = 0x0004;
const KEY_USAGE_DATA_ENCIPHERMENT: u16 = 0x0008;
const KEY_USAGE_KEY_AGREEMENT: u16 = 0x0010;
const KEY_USAGE_KEY_CERT_SIGN: u16 = 0x0020;
const KEY_USAGE_CRL_SIGN: u16 = 0x0040;
const KEY_USAGE_ENCIPHER_ONLY: u16 = 0x0080;
const KEY_USAGE_DECIPHER_ONLY: u16 = 0x0100;

#[allow(unused_assignments)]
pub fn print_key_usage(t: TLVElement) -> Result<(), Error> {
    println!("    X509v3 Key Usage: critical");
    // TODO This should be u16, but we get u8 for now
    let key_usage = t.get_u8()? as u16;
    let mut comma = "        ";
    if (key_usage & KEY_USAGE_DIGITAL_SIGN) != 0 {
        print!("{} digitalSignature", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_NON_REPUDIATION) != 0 {
        print!("{} nonRepudiation", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_KEY_ENCIPHERMENT) != 0 {
        print!("{} keyEncipherment", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_DATA_ENCIPHERMENT) != 0 {
        print!("{} dataEncipherment", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_KEY_AGREEMENT) != 0 {
        print!("{} keyAgreement", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_KEY_CERT_SIGN) != 0 {
        print!("{} keyCertSign", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_CRL_SIGN) != 0 {
        print!("{} CRLSign", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_ENCIPHER_ONLY) != 0 {
        print!("{} encipherOnly", comma);
        comma = ",";
    }
    if (key_usage & KEY_USAGE_DECIPHER_ONLY) != 0 {
        print!("{} decipherOnly", comma);
        comma = ",";
    }
    println!();
    Ok(())
}

pub fn print_extended_key_usage(t: TLVElement) -> Result<(), Error> {
    println!("    X509v3 Extended Key Usage:");
    let iter = t.confirm_array()?.iter().ok_or(Error::Invalid)?;
    let mut comma = "        ";
    for t in iter {
        print!("{}{}", comma, t.get_u8()?);
        comma = ",";
    }
    println!();
    Ok(())
}

pub fn print_basic_constraints(t: TLVElement) -> Result<(), Error> {
    println!("    X509v3 Basic Constraints:");
    let iter = t.confirm_struct()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                1 => println!("        CA = {:?}", t.get_bool()?),
                2 => println!("        Path Len = {:?}", t.get_u8()?),
                _ => println!("Unsupport Tag"),
            }
        }
    }
    Ok(())
}

#[derive(FromPrimitive)]
pub enum ExtTags {
    BasicConstraints = 1,
    KeyUsage = 2,
    ExtKeyUsage = 3,
    SubjectKeyId = 4,
    AuthKeyId = 5,
    FutureExt = 6,
}
pub fn print_extensions(t: TLVElement) -> Result<(), Error> {
    println!("X509v3 extensions:");
    let iter = t.confirm_list()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                ExtTags::BasicConstraints => print_basic_constraints(t)?,
                ExtTags::KeyUsage => print_key_usage(t)?,
                ExtTags::ExtKeyUsage => print_extended_key_usage(t)?,
                ExtTags::SubjectKeyId => println!("    Subject Key Id: {:x?}", t.get_slice()?),
                ExtTags::AuthKeyId => println!("    Authority Key Id: {:x?}", t.get_slice()?),
                ExtTags::FutureExt => println!("    Future Extensions: {:x?}", t.get_slice()?),
            }
        }
    }
    Ok(())
}

#[derive(FromPrimitive)]
pub enum DnTags {
    NodeId = 17,
    FirmwareSignId = 18,
    IcaId = 19,
    RootCaId = 20,
    FabricId = 21,
    NocCat = 22,
}
pub fn print_dn_list(t: TLVElement) -> Result<(), Error> {
    let iter = t.confirm_list()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                DnTags::NodeId => println!("    Chip Node Id = {:x?}", t.get_u32()?),
                DnTags::FirmwareSignId => {
                    println!("    Chip Firmware Signing Id = {:?}", t.get_u8()?)
                }
                DnTags::IcaId => println!("    Chip ICA Id = {:?}", t.get_u8()?),
                DnTags::RootCaId => println!("    Chip Root CA Id = {:?}", t.get_u8()?),
                DnTags::FabricId => println!("    Chip Fabric Id = {:?}", t.get_u8()?),
                DnTags::NocCat => println!("    Chip NOC CAT = {:?}", t.get_u8()?),
            }
        }
    }
    Ok(())
}

pub struct Cert(Vec<u8>);

impl Cert {
    pub fn new(cert_bin: &[u8]) -> Self {
        Self(cert_bin.to_vec())
    }

    pub fn get_node_id(&self) -> Result<u64, Error> {
        tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::Subject as u32)?
            .confirm_list()?
            .find_tag(DnTags::NodeId as u32)
            .map_err(|_e| Error::NoNodeId)?
            .get_u32()
            .map(|e| e as u64)
    }

    pub fn get_fabric_id(&self) -> Result<u64, Error> {
        tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::Subject as u32)?
            .confirm_list()?
            .find_tag(DnTags::FabricId as u32)
            .map_err(|_e| Error::NoFabricId)?
            .get_u8()
            .map(|e| e as u64)
    }

    pub fn get_pubkey(&self) -> Result<&[u8], Error> {
        tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::EcPubKey as u32)
            .map_err(|_e| Error::Invalid)?
            .get_slice()
    }

    pub fn get_subject_key_id(&self) -> Result<&[u8], Error> {
        tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::Extensions as u32)
            .map_err(|_e| Error::Invalid)?
            .confirm_list()?
            .find_tag(ExtTags::SubjectKeyId as u32)
            .map_err(|_e| Error::Invalid)?
            .get_slice()
    }

    pub fn is_authority(&self, their: &Cert) -> Result<bool, Error> {
        let our_auth = tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::Extensions as u32)
            .map_err(|_e| Error::Invalid)?
            .confirm_list()?
            .find_tag(ExtTags::AuthKeyId as u32)
            .map_err(|_e| Error::Invalid)?
            .get_slice()?;

        let their_subject = their.get_subject_key_id()?;
        if our_auth == their_subject {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn as_slice(&self) -> Result<&[u8], Error> {
        Ok(self.0.as_slice())
    }
}

impl Default for Cert {
    fn default() -> Self {
        Self(Vec::with_capacity(0))
    }
}

pub fn print_cert(buf: &[u8]) -> Result<(), Error> {
    let iter = tlv::get_root_node_struct(buf)?.iter().unwrap();

    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                CertTags::SerialNum => println!("Serial Number: {:x?}", t.get_slice()?),
                CertTags::SignAlgo => println!(
                    "Signature Algorithm: {:?}",
                    get_sign_algo(t.get_u8()?).ok_or(Error::Invalid)?
                ),
                CertTags::Issuer => {
                    println!("Issuer:");
                    print_dn_list(t)?;
                }
                CertTags::NotBefore => println!("Not Before: {:?}", t.get_u32()?),
                CertTags::NotAfter => println!("Not After: {:?}", t.get_u32()?),
                CertTags::Subject => {
                    println!("Subject:");
                    print_dn_list(t)?;
                }
                CertTags::PubKeyAlgo => println!(
                    "Public Key Algorithm: {:?}",
                    get_pubkey_algo(t.get_u8()?).ok_or(Error::Invalid)?,
                ),
                CertTags::EcCurveId => println!(
                    "Elliptic Curve: {:?}",
                    get_ec_curve_id(t.get_u8()?).ok_or(Error::Invalid)?
                ),
                CertTags::EcPubKey => println!("Public-Key: {:x?}", t.get_slice()?),
                CertTags::Extensions => print_extensions(t)?,
                CertTags::Signature => println!("Signature: {:x?}", t.get_slice()?),
            }
        }
    }
    Ok(())
}
