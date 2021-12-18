use crate::{
    error::Error,
    tlv::{self, TLVElement},
    tlv_common::TagType,
};
use num_derive::FromPrimitive;

#[derive(FromPrimitive, Debug)]
pub enum EcCurveId {
    Prime256V1 = 1,
}

pub fn get_ec_curve_id(algo: u8) -> Option<EcCurveId> {
    num::FromPrimitive::from_u8(algo)
}

#[derive(FromPrimitive, Debug)]
pub enum PubKeyAlgo {
    EcPubKey = 1,
}

pub fn get_pubkey_algo(algo: u8) -> Option<PubKeyAlgo> {
    num::FromPrimitive::from_u8(algo)
}

#[derive(FromPrimitive, Debug)]
pub enum SignAlgo {
    ECDSAWithSHA256 = 1,
}

pub fn get_sign_algo(algo: u8) -> Option<SignAlgo> {
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
    let key_usage = t.get_u8().ok_or(Error::Invalid)? as u16;
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
    println!("");
    Ok(())
}

pub fn print_extended_key_usage(t: TLVElement) -> Result<(), Error> {
    println!("    X509v3 Extended Key Usage:");
    let mut iter = t
        .confirm_array()
        .ok_or(Error::Invalid)?
        .into_iter()
        .ok_or(Error::Invalid)?;
    let mut comma = "        ";
    while let Some(t) = iter.next() {
        print!("{}{}", comma, t.get_u8().ok_or(Error::Invalid)?);
        comma = ",";
    }
    println!("");
    Ok(())
}

pub fn print_basic_constraints(t: TLVElement) -> Result<(), Error> {
    println!("    X509v3 Basic Constraints:");
    let mut iter = t
        .confirm_struct()
        .ok_or(Error::Invalid)?
        .into_iter()
        .ok_or(Error::Invalid)?;
    while let Some(t) = iter.next() {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                1 => println!("        CA = {:?}", t.get_bool().ok_or(Error::Invalid)?),
                2 => println!("        Path Len = {:?}", t.get_u8().ok_or(Error::Invalid)?),
                _ => println!("Unsupport Tag"),
            }
        }
    }
    Ok(())
}

pub fn print_extensions(t: TLVElement) -> Result<(), Error> {
    println!("X509v3 extensions:");
    let mut iter = t
        .confirm_list()
        .ok_or(Error::Invalid)?
        .into_iter()
        .ok_or(Error::Invalid)?;
    while let Some(t) = iter.next() {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                1 => print_basic_constraints(t)?,
                2 => print_key_usage(t)?,
                3 => print_extended_key_usage(t)?,
                4 => println!(
                    "    Subject Key Id: {:x?}",
                    t.get_slice().ok_or(Error::Invalid)?
                ),
                5 => println!(
                    "    Authority Key Id: {:x?}",
                    t.get_slice().ok_or(Error::Invalid)?
                ),
                6 => println!(
                    "    Future Extensions: {:x?}",
                    t.get_slice().ok_or(Error::Invalid)?
                ),
                _ => println!("Unsupported Tag"),
            }
        }
    }
    Ok(())
}

pub fn print_dn_list(t: TLVElement) -> Result<(), Error> {
    let mut iter = t
        .confirm_list()
        .ok_or(Error::Invalid)?
        .into_iter()
        .ok_or(Error::Invalid)?;
    while let Some(t) = iter.next() {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                17 => println!(
                    "    Chip Node Id = {:x?}",
                    t.get_u64().ok_or(Error::Invalid)?
                ),
                18 => println!(
                    "    Chip Firmware Signing Id = {:?}",
                    t.get_u8().ok_or(Error::Invalid)?
                ),
                19 => println!("    Chip ICA Id = {:?}", t.get_u8().ok_or(Error::Invalid)?),
                20 => println!(
                    "    Chip Root CA Id = {:?}",
                    t.get_u8().ok_or(Error::Invalid)?
                ),
                21 => println!(
                    "    Chip Fabric Id = {:?}",
                    t.get_u8().ok_or(Error::Invalid)?
                ),
                22 => println!("    Chip NOC AT1 = {:?}", t.get_u8().ok_or(Error::Invalid)?),
                23 => println!("    Chip NOC AT2 = {:?}", t.get_u8().ok_or(Error::Invalid)?),
                _ => println!("Unsupported tag"),
            }
        }
    }
    Ok(())
}

pub fn print_cert(buf: &[u8]) -> Result<(), Error> {
    let mut iter = tlv::get_root_node_struct(buf)
        .ok_or(Error::Invalid)?
        .into_iter()
        .unwrap();

    while let Some(t) = iter.next() {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                1 => println!("Serial Number: {:x?}", t.get_slice().ok_or(Error::Invalid)?),
                2 => println!(
                    "Signature Algorithm: {:?}",
                    get_sign_algo(t.get_u8().ok_or(Error::Invalid)?).ok_or(Error::Invalid)?
                ),
                3 => {
                    println!("Issuer:");
                    print_dn_list(t)?;
                }
                4 => println!("Not Before: {:?}", t.get_u32().ok_or(Error::Invalid)?),
                5 => println!("Not After: {:?}", t.get_u32().ok_or(Error::Invalid)?),
                6 => {
                    println!("Subject:");
                    print_dn_list(t)?;
                }
                7 => println!(
                    "Public Key Algorithm: {:?}",
                    get_pubkey_algo(t.get_u8().ok_or(Error::Invalid)?).ok_or(Error::Invalid)?,
                ),
                8 => println!(
                    "Elliptic Curve: {:?}",
                    get_ec_curve_id(t.get_u8().ok_or(Error::Invalid)?).ok_or(Error::Invalid)?
                ),
                9 => println!("Public-Key: {:?}", t.get_slice().ok_or(Error::Invalid)?),
                10 => print_extensions(t)?,
                11 => println!("Signature: {:x?}", t.get_slice().ok_or(Error::Invalid)?),
                _ => println!("Unsupported tag\n"),
            }
        }
    }
    Ok(())
}
