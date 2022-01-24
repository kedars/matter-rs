use std::fmt;

use crate::{
    error::Error,
    tlv::{self, TLVContainerIterator, TLVElement},
    tlv_common::TagType,
};
use chrono::{TimeZone, Utc};
use log::error;
use num_derive::FromPrimitive;

// As per https://datatracker.ietf.org/doc/html/rfc5280

const OID_PUB_KEY_ECPUBKEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_EC_TYPE_PRIME256V1: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

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

fn reverse_byte(byte: u8) -> u8 {
    const LOOKUP: [u8; 16] = [
        0x00, 0x08, 0x04, 0x0c, 0x02, 0x0a, 0x06, 0x0e, 0x01, 0x09, 0x05, 0x0d, 0x03, 0x0b, 0x07,
        0x0f,
    ];
    (LOOKUP[(byte & 0x0f) as usize] << 4) | LOOKUP[(byte >> 4) as usize]
}

fn int_to_bitstring(mut a: u16, buf: &mut [u8]) {
    if buf.len() >= 2 {
        buf[0] = reverse_byte((a & 0xff) as u8);
        a >>= 8;
        buf[1] = reverse_byte((a & 0xff) as u8);
    }
}

macro_rules! add_if {
    ($key:ident, $bit:ident,$str:literal) => {
        if ($key & $bit) != 0 {
            $str
        } else {
            ""
        }
    };
}

fn get_print_str(key_usage: u16) -> String {
    format!(
        "{}{}{}{}{}{}{}{}{}",
        add_if!(key_usage, KEY_USAGE_DIGITAL_SIGN, "digitalSignature "),
        add_if!(key_usage, KEY_USAGE_NON_REPUDIATION, "nonRepudiation "),
        add_if!(key_usage, KEY_USAGE_KEY_ENCIPHERMENT, "keyEncipherment"),
        add_if!(key_usage, KEY_USAGE_DATA_ENCIPHERMENT, "dataEncipherment"),
        add_if!(key_usage, KEY_USAGE_KEY_AGREEMENT, "keyAgreement"),
        add_if!(key_usage, KEY_USAGE_KEY_CERT_SIGN, "keyCertSign"),
        add_if!(key_usage, KEY_USAGE_CRL_SIGN, "CRLSign"),
        add_if!(key_usage, KEY_USAGE_ENCIPHER_ONLY, "encipherOnly"),
        add_if!(key_usage, KEY_USAGE_DECIPHER_ONLY, "decipherOnly"),
    )
}

#[allow(unused_assignments)]
pub fn decode_key_usage(t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
    // TODO This should be u16, but we get u8 for now
    let key_usage = t.get_u8()? as u16;
    let mut key_usage_str = [0u8; 2];
    int_to_bitstring(key_usage, &mut key_usage_str);
    w.bitstr(&get_print_str(key_usage), true, &key_usage_str)?;
    Ok(())
}

pub fn decode_extended_key_usage(t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
    const OID_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    const OID_CLIENT_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    const OID_CODE_SIGN: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
    const OID_EMAIL_PROT: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
    const OID_TIMESTAMP: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08];
    const OID_OCSP_SIGN: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09];

    let iter = t.confirm_array()?.iter().ok_or(Error::Invalid)?;
    w.start_seq("")?;
    for t in iter {
        let (str, oid) = match t.get_u8()? {
            1 => ("ServerAuth", OID_SERVER_AUTH),
            2 => ("ClientAuth", OID_CLIENT_AUTH),
            3 => ("CodeSign", OID_CODE_SIGN),
            4 => ("EmailProtection", OID_EMAIL_PROT),
            5 => ("Timestamp", OID_TIMESTAMP),
            6 => ("OCSPSign", OID_OCSP_SIGN),
            _ => {
                error!("Not Supported");
                return Err(Error::Invalid);
            }
        };
        w.oid(&str, &oid)?;
    }
    w.end_seq()?;
    Ok(())
}

pub fn decode_basic_constraints(t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
    w.start_seq("")?;
    let iter = t.confirm_struct()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            match tag {
                1 => {
                    if t.get_bool()? {
                        // Encode CA only if true
                        w.bool("CA:", true)?
                    }
                }

                2 => error!("Path Len is not yet implemented"),
                _ => error!("Unsupport Tag"),
            }
        }
    }
    w.end_seq()
}

pub fn decode_extension_start(
    tag: &str,
    critical: bool,
    oid: &[u8],
    w: &mut dyn CertConsumer,
) -> Result<(), Error> {
    w.start_seq(tag)?;
    w.oid("", oid)?;
    if critical {
        w.bool("critical:", true)?;
    }
    w.start_compound_ostr("value:")
}

pub fn decode_extension_end(w: &mut dyn CertConsumer) -> Result<(), Error> {
    w.end_compound_ostr()?;
    w.end_seq()
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
pub fn decode_extensions(t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
    const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
    const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];
    const OID_EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x25];
    const OID_SUBJ_KEY_IDENTIFIER: [u8; 3] = [0x55, 0x1D, 0x0E];
    const OID_AUTH_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x23];

    w.start_ctx("X509v3 extensions:", 3)?;
    w.start_seq("")?;
    let iter = t.confirm_list()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                ExtTags::BasicConstraints => {
                    decode_extension_start(
                        "X509v3 Basic Constraints",
                        true,
                        &OID_BASIC_CONSTRAINTS,
                        w,
                    )?;
                    decode_basic_constraints(t, w)?;
                    decode_extension_end(w)?;
                }
                ExtTags::KeyUsage => {
                    decode_extension_start("X509v3 Key Usage", true, &OID_KEY_USAGE, w)?;
                    decode_key_usage(t, w)?;
                    decode_extension_end(w)?;
                }
                ExtTags::ExtKeyUsage => {
                    decode_extension_start(
                        "X509v3 Extended Key Usage",
                        true,
                        &OID_EXT_KEY_USAGE,
                        w,
                    )?;
                    decode_extended_key_usage(t, w)?;
                    decode_extension_end(w)?;
                }
                ExtTags::SubjectKeyId => {
                    decode_extension_start("Subject Key ID", false, &OID_SUBJ_KEY_IDENTIFIER, w)?;
                    w.ostr("", t.get_slice()?)?;
                    decode_extension_end(w)?;
                }
                ExtTags::AuthKeyId => {
                    decode_extension_start("Auth Key ID", false, &OID_AUTH_KEY_ID, w)?;
                    w.start_seq("")?;
                    w.ctx("", 0, t.get_slice()?)?;
                    w.end_seq()?;
                    decode_extension_end(w)?;
                }
                ExtTags::FutureExt => {
                    error!("Future Extensions Not Yet Supported: {:x?}", t.get_slice()?)
                }
            }
        }
    }
    w.end_seq()?;
    w.end_ctx()?;
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
pub fn decode_dn_list(tag: &str, t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
    const OID_MATTER_NODE_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x01];
    const OID_MATTER_FW_SIGN_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x02];
    const OID_MATTER_ICA_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x03];
    const OID_MATTER_ROOT_CA_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x04];
    const OID_MATTER_FABRIC_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x05];
    const OID_MATTER_NOC_CAT_ID: [u8; 10] =
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x06];

    let iter = t.confirm_list()?.iter().ok_or(Error::Invalid)?;
    w.start_seq(tag)?;
    for t in iter {
        w.start_set("")?;
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                DnTags::NodeId => {
                    w.start_seq("")?;
                    w.oid("Chip Node Id:", &OID_MATTER_NODE_ID)?;
                    w.utf8str("", format!("{:016X}", t.get_u32()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::FirmwareSignId => {
                    w.start_seq("")?;
                    w.oid("Chip Firmware Signing Id:", &OID_MATTER_FW_SIGN_ID)?;
                    w.utf8str("", format!("{:016X}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::IcaId => {
                    w.start_seq("")?;
                    w.oid("Chip ICA Id:", &OID_MATTER_ICA_ID)?;
                    w.utf8str("", format!("{:016X}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::RootCaId => {
                    w.start_seq("")?;
                    w.oid("Chip Root CA Id:", &OID_MATTER_ROOT_CA_ID)?;
                    w.utf8str("", format!("{:016X}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::FabricId => {
                    w.start_seq("")?;
                    w.oid("Chip Fabric Id:", &OID_MATTER_FABRIC_ID)?;
                    w.utf8str("", format!("{:016X}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::NocCat => {
                    w.start_seq("")?;
                    w.oid("Chip NOC CAT Id:", &OID_MATTER_NOC_CAT_ID)?;
                    w.utf8str("", format!("{:08X}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
            }
        }
        w.end_set()?;
    }
    w.end_seq()?;
    Ok(())
}

fn get_next_tag<'a>(
    iter: &mut TLVContainerIterator<'a>,
    tag: CertTags,
) -> Result<TLVElement<'a>, Error> {
    let current = iter.next().ok_or(Error::Invalid)?;
    if current.get_tag() != TagType::Context(tag as u8) {
        Err(Error::TLVTypeMismatch)
    } else {
        Ok(current)
    }
}

pub fn decode_cert(buf: &[u8], w: &mut dyn CertConsumer) -> Result<(), Error> {
    let mut iter = tlv::get_root_node_struct(buf)?.iter().unwrap();

    w.start_seq("")?;

    w.start_ctx("Version:", 0)?;
    w.integer("", &[2])?;
    w.end_ctx()?;

    let mut current = get_next_tag(&mut iter, CertTags::SerialNum)?;
    w.integer("Serial Num:", current.get_slice()?)?;

    current = get_next_tag(&mut iter, CertTags::SignAlgo)?;
    w.start_seq("Signature Algorithm:")?;
    let (str, oid) = match get_sign_algo(current.get_u8()?).ok_or(Error::Invalid)? {
        SignAlgoValue::ECDSAWithSHA256 => ("ECDSA with SHA256", OID_ECDSA_WITH_SHA256),
    };
    w.oid(str, &oid)?;
    w.end_seq()?;

    current = get_next_tag(&mut iter, CertTags::Issuer)?;
    decode_dn_list("Issuer:", current, w)?;

    w.start_seq("Validity:")?;
    current = get_next_tag(&mut iter, CertTags::NotBefore)?;
    w.utctime("Not Before:", current.get_u32()?)?;
    current = get_next_tag(&mut iter, CertTags::NotAfter)?;
    w.utctime("Not After:", current.get_u32()?)?;
    w.end_seq()?;

    current = get_next_tag(&mut iter, CertTags::Subject)?;
    decode_dn_list("Subject:", current, w)?;

    w.start_seq("")?;
    w.start_seq("Public Key Algorithm")?;
    current = get_next_tag(&mut iter, CertTags::PubKeyAlgo)?;
    let (str, pub_key) = match get_pubkey_algo(current.get_u8()?).ok_or(Error::Invalid)? {
        PubKeyAlgoValue::EcPubKey => ("ECPubKey", OID_PUB_KEY_ECPUBKEY),
    };
    w.oid(&str, &pub_key)?;
    current = get_next_tag(&mut iter, CertTags::EcCurveId)?;
    let (str, curve_id) = match get_ec_curve_id(current.get_u8()?).ok_or(Error::Invalid)? {
        EcCurveIdValue::Prime256V1 => ("Prime256v1", OID_EC_TYPE_PRIME256V1),
    };
    w.oid(&str, &curve_id)?;
    w.end_seq()?;

    current = get_next_tag(&mut iter, CertTags::EcPubKey)?;
    w.bitstr("Public-Key:", false, current.get_slice()?)?;
    w.end_seq()?;

    current = get_next_tag(&mut iter, CertTags::Extensions)?;
    decode_extensions(current, w)?;

    // We do not encode the Signature in the DER certificate

    w.end_seq()
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

    pub fn get_signature(&self) -> Result<&[u8], Error> {
        tlv::get_root_node_struct(self.0.as_slice())?
            .find_tag(CertTags::Signature as u32)
            .map_err(|_e| Error::Invalid)?
            .get_slice()
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

impl fmt::Display for Cert {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut printer = CertPrinter::new(f);
        let _ = decode_cert(self.0.as_slice(), &mut printer)
            .map_err(|e| error!("Error decoding certificate: {}", e));
        // Signature is not encoded by the Cert Decoder
        writeln!(
            f,
            "Signature: {:x?}",
            self.get_signature()
                .map_err(|e| error!("Error decoding signature: {}", e))
        )
    }
}

pub trait CertConsumer {
    fn start_seq(&mut self, tag: &str) -> Result<(), Error>;
    fn end_seq(&mut self) -> Result<(), Error>;
    fn integer(&mut self, tag: &str, i: &[u8]) -> Result<(), Error>;
    fn utf8str(&mut self, tag: &str, s: &str) -> Result<(), Error>;
    fn bitstr(&mut self, tag: &str, truncate: bool, s: &[u8]) -> Result<(), Error>;
    fn ostr(&mut self, tag: &str, s: &[u8]) -> Result<(), Error>;
    fn start_compound_ostr(&mut self, tag: &str) -> Result<(), Error>;
    fn end_compound_ostr(&mut self) -> Result<(), Error>;
    fn bool(&mut self, tag: &str, b: bool) -> Result<(), Error>;
    fn start_set(&mut self, tag: &str) -> Result<(), Error>;
    fn end_set(&mut self) -> Result<(), Error>;
    fn ctx(&mut self, tag: &str, id: u8, val: &[u8]) -> Result<(), Error>;
    fn start_ctx(&mut self, tag: &str, id: u8) -> Result<(), Error>;
    fn end_ctx(&mut self) -> Result<(), Error>;
    fn oid(&mut self, tag: &str, oid: &[u8]) -> Result<(), Error>;
    fn utctime(&mut self, tag: &str, epoch: u32) -> Result<(), Error>;
}

pub struct CertPrinter<'a, 'b> {
    level: usize,
    f: &'b mut fmt::Formatter<'a>,
}

impl<'a, 'b> CertPrinter<'a, 'b> {
    pub fn new(f: &'b mut fmt::Formatter<'a>) -> Self {
        Self { level: 0, f }
    }
}

const MAX_DEPTH: usize = 10;
const SPACE: [&str; MAX_DEPTH] = [
    "",
    "",
    "    ",
    "        ",
    "            ",
    "                ",
    "                    ",
    "                        ",
    "                            ",
    "                                ",
];

impl<'a, 'b> CertConsumer for CertPrinter<'a, 'b> {
    fn start_seq(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_seq(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn integer(&mut self, tag: &str, i: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, i);
        Ok(())
    }
    fn utf8str(&mut self, tag: &str, s: &str) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn bitstr(&mut self, tag: &str, _truncate: bool, s: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn ostr(&mut self, tag: &str, s: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn start_compound_ostr(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_compound_ostr(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn bool(&mut self, tag: &str, b: bool) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} {}", SPACE[self.level], tag, b);
        Ok(())
    }
    fn start_set(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_set(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn ctx(&mut self, tag: &str, id: u8, val: &[u8]) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {}[{}]{:x?}", SPACE[self.level], tag, id, val);
        Ok(())
    }
    fn start_ctx(&mut self, tag: &str, val: u8) -> Result<(), Error> {
        let _ = writeln!(self.f, "{} {} [{}]", SPACE[self.level], tag, val);
        self.level += 1;
        Ok(())
    }
    fn end_ctx(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn oid(&mut self, tag: &str, _oid: &[u8]) -> Result<(), Error> {
        if tag.len() != 0 {
            let _ = writeln!(self.f, "{} {}", SPACE[self.level], tag);
        }
        Ok(())
    }
    fn utctime(&mut self, tag: &str, epoch: u32) -> Result<(), Error> {
        let mut matter_epoch = Utc.ymd(2000, 1, 1).and_hms(0, 0, 0).timestamp();
        matter_epoch += epoch as i64;
        let _ = writeln!(
            self.f,
            "{} {} {}",
            SPACE[self.level],
            tag,
            Utc.timestamp(matter_epoch, 0)
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct ASN1Writer<'a> {
    buf: &'a mut [u8],
    // The current write offset in the buffer
    offset: usize,
    // If multiple 'composite' structures are being written, their starts are
    // captured in this
    depth: [usize; MAX_DEPTH],
    // The current depth of operation within the depth stack
    current_depth: usize,
}

const RESERVE_LEN_BYTES: usize = 3;
impl<'a> ASN1Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self {
            buf,
            offset: 0,
            depth: [0; MAX_DEPTH],
            current_depth: 0,
        }
    }

    pub fn append_with<F>(&mut self, size: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        if self.offset + size <= self.buf.len() {
            f(self);
            self.offset += size;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    pub fn append_tlv<F>(&mut self, tag: u8, len: usize, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut Self),
    {
        let total_len = 1 + ASN1Writer::bytes_to_encode_len(len)? + len;
        if self.offset + total_len <= self.buf.len() {
            self.buf[self.offset] = tag;
            self.offset += 1;
            self.offset = self.encode_len(self.offset, len)?;
            f(self);
            self.offset += len;
            return Ok(());
        }
        Err(Error::NoSpace)
    }

    fn add_compound(&mut self, val: u8) -> Result<(), Error> {
        // We reserve 3 bytes for encoding the length
        // If a shorter length is actually required, we will move everything back
        self.append_with(1 + RESERVE_LEN_BYTES, |t| t.buf[t.offset] = val)?;
        self.depth[self.current_depth] = self.offset;
        self.current_depth += 1;
        if self.current_depth >= MAX_DEPTH {
            Err(Error::NoSpace)
        } else {
            Ok(())
        }
    }

    fn encode_len(&mut self, mut at_offset: usize, len: usize) -> Result<usize, Error> {
        let mut bytes_of_len = ASN1Writer::bytes_to_encode_len(len)?;
        if bytes_of_len > 1 {
            self.buf[at_offset] = (0x80 | bytes_of_len - 1) as u8;
            at_offset += 1;
            bytes_of_len -= 1;
        }

        // At this point bytes_of_len is the actual number of bytes for the length encoding
        // after the 0x80 (if it was present)
        let mut octet_number = bytes_of_len - 1;
        // We start encoding the highest octest first
        loop {
            self.buf[at_offset] = ((len >> (octet_number * 8)) & 0xff) as u8;

            at_offset += 1;
            if octet_number == 0 {
                break;
            }
            octet_number -= 1;
        }

        Ok(at_offset)
    }

    fn end_compound(&mut self) -> Result<(), Error> {
        if self.current_depth == 0 {
            return Err(Error::Invalid);
        }
        let seq_len = self.get_compound_len();
        let write_offset = self.get_length_encoding_offset();

        let mut write_offset = self.encode_len(write_offset, seq_len)?;

        // Shift everything by as much
        let shift_len = self.depth[self.current_depth - 1] - write_offset;
        if shift_len > 0 {
            for _i in 0..seq_len {
                self.buf[write_offset] = self.buf[write_offset + shift_len];
                write_offset += 1;
            }
        }
        self.current_depth -= 1;
        self.offset -= shift_len;
        Ok(())
    }

    fn get_compound_len(&self) -> usize {
        self.offset - self.depth[self.current_depth - 1]
    }

    fn bytes_to_encode_len(len: usize) -> Result<usize, Error> {
        let len = if len < 128 {
            // This is directly encoded
            1
        } else if len < 256 {
            // This is done with an 0xA1 followed by actual len
            2
        } else if len < 65536 {
            // This is done with an 0xA2 followed by 2 bytes of actual len
            3
        } else {
            return Err(Error::NoSpace);
        };
        Ok(len)
    }

    fn get_length_encoding_offset(&self) -> usize {
        self.depth[self.current_depth - 1] - RESERVE_LEN_BYTES
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.offset]
    }

    fn write_str(&mut self, vtype: u8, s: &[u8]) -> Result<(), Error> {
        self.append_tlv(vtype, s.len(), |t| {
            let end_offset = t.offset + s.len();
            t.buf[t.offset..end_offset].copy_from_slice(s);
        })
    }
}

impl<'a> CertConsumer for ASN1Writer<'a> {
    fn start_seq(&mut self, _tag: &str) -> Result<(), Error> {
        self.add_compound(0x30)
    }

    fn end_seq(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn integer(&mut self, _tag: &str, i: &[u8]) -> Result<(), Error> {
        self.write_str(0x02, i)
    }

    fn utf8str(&mut self, _tag: &str, s: &str) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is UTF8String
        self.write_str(0x0c, s.as_bytes())
    }

    fn bitstr(&mut self, _tag: &str, truncate: bool, s: &[u8]) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is BIT String

        // Strip off the end zeroes
        let mut last_byte = s.len() - 1;
        let mut num_of_zero = 0;
        if truncate {
            while s[last_byte] == 0 {
                last_byte -= 1;
            }
            // For the last valid byte, identifying the number of last bits
            // that are 0s
            num_of_zero = s[last_byte].trailing_zeros() as u8;
        }
        let s = &s[..(last_byte + 1)];
        self.append_tlv(0x03, s.len() + 1, |t| {
            t.buf[t.offset] = num_of_zero;
            let end_offset = t.offset + 1 + s.len();
            t.buf[(t.offset + 1)..end_offset].copy_from_slice(s);
        })
    }

    fn ostr(&mut self, _tag: &str, s: &[u8]) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is Octet String
        self.write_str(0x04, s)
    }

    fn start_compound_ostr(&mut self, _tag: &str) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is compound Octet String
        self.add_compound(0x04)
    }

    fn end_compound_ostr(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn bool(&mut self, _tag: &str, b: bool) -> Result<(), Error> {
        self.append_tlv(0x01, 1, |t| {
            if b {
                t.buf[t.offset] = 0xFF;
            } else {
                t.buf[t.offset] = 0x00;
            }
        })
    }

    fn start_set(&mut self, _tag: &str) -> Result<(), Error> {
        self.add_compound(0x31)
    }

    fn end_set(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn ctx(&mut self, _tag: &str, id: u8, val: &[u8]) -> Result<(), Error> {
        self.write_str(0x80 | id, val)
    }

    fn start_ctx(&mut self, _tag: &str, val: u8) -> Result<(), Error> {
        self.add_compound(0xA0 | val)
    }

    fn end_ctx(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn oid(&mut self, _tag: &str, oid: &[u8]) -> Result<(), Error> {
        self.write_str(0x06, oid)
    }

    fn utctime(&mut self, _tag: &str, epoch: u32) -> Result<(), Error> {
        let mut matter_epoch = Utc.ymd(2000, 1, 1).and_hms(0, 0, 0).timestamp();
        matter_epoch += epoch as i64;

        let dt = Utc.timestamp(matter_epoch, 0);
        let time_str = format!("{}Z", dt.format("%y%m%d%H%M%S"));
        self.write_str(0x17, time_str.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use crate::cert::{decode_cert, ASN1Writer};

    #[test]
    fn test_success_decode() {
        let test_input1 = [
            0x15, 0x30, 0x01, 0x01, 0x00, 0x24, 0x02, 0x01, 0x37, 0x03, 0x24, 0x14, 0x00, 0x24,
            0x15, 0x03, 0x18, 0x26, 0x04, 0x80, 0x22, 0x81, 0x27, 0x26, 0x05, 0x80, 0x25, 0x4d,
            0x3a, 0x37, 0x06, 0x24, 0x13, 0x01, 0x24, 0x15, 0x03, 0x18, 0x24, 0x07, 0x01, 0x24,
            0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x69, 0xda, 0xe9, 0x42, 0x88, 0xcf, 0x64, 0x94,
            0x2d, 0xd5, 0x0a, 0x74, 0x2d, 0x50, 0xe8, 0x5e, 0xbe, 0x15, 0x53, 0x24, 0xe5, 0xc5,
            0x6b, 0xe5, 0x7f, 0xc1, 0x41, 0x11, 0x21, 0xdd, 0x46, 0xa3, 0x0d, 0x63, 0xc3, 0xe3,
            0x90, 0x7a, 0x69, 0x64, 0xdd, 0x66, 0x78, 0x10, 0xa6, 0xc8, 0x0f, 0xfd, 0xb6, 0xf2,
            0x9b, 0x88, 0x50, 0x93, 0x77, 0x9e, 0xf7, 0xb4, 0xda, 0x94, 0x11, 0x33, 0x1e, 0xfe,
            0x37, 0x0a, 0x35, 0x01, 0x29, 0x01, 0x18, 0x24, 0x02, 0x60, 0x30, 0x04, 0x14, 0xdf,
            0xfb, 0x79, 0xf1, 0x2b, 0xbf, 0x68, 0x18, 0x59, 0x7f, 0xf7, 0xe8, 0xaf, 0x88, 0x91,
            0x1c, 0x72, 0x32, 0xf7, 0x52, 0x30, 0x05, 0x14, 0xed, 0x31, 0x5e, 0x1a, 0xb7, 0xb9,
            0x7a, 0xca, 0x04, 0x79, 0x5d, 0x82, 0x57, 0x7a, 0xd7, 0x0a, 0x75, 0xd0, 0xdb, 0x7a,
            0x18, 0x30, 0x0b, 0x40, 0xe5, 0xd4, 0xe6, 0x0e, 0x98, 0x62, 0x2f, 0xaa, 0x59, 0xe0,
            0x28, 0x59, 0xc2, 0xd4, 0xcd, 0x34, 0x85, 0x7f, 0x93, 0xbe, 0x14, 0x35, 0xa3, 0x76,
            0x8a, 0xc9, 0x2f, 0x59, 0x39, 0xa0, 0xb0, 0x75, 0xe8, 0x8e, 0x11, 0xa9, 0xc1, 0x9e,
            0xaa, 0xab, 0xa0, 0xdb, 0xb4, 0x79, 0x63, 0xfc, 0x02, 0x03, 0x27, 0x25, 0xac, 0x21,
            0x6f, 0xef, 0x27, 0xab, 0x0f, 0x90, 0x09, 0x99, 0x05, 0xa8, 0x60, 0xd8, 0x18,
        ];
        let test_input2 = [
            0x15, 0x30, 0x01, 0x01, 0x01, 0x24, 0x02, 0x01, 0x37, 0x03, 0x24, 0x13, 0x01, 0x24,
            0x15, 0x03, 0x18, 0x26, 0x04, 0x80, 0x22, 0x81, 0x27, 0x26, 0x05, 0x80, 0x25, 0x4d,
            0x3a, 0x37, 0x06, 0x26, 0x11, 0x69, 0xb6, 0x01, 0x00, 0x24, 0x15, 0x03, 0x18, 0x24,
            0x07, 0x01, 0x24, 0x08, 0x01, 0x30, 0x09, 0x41, 0x04, 0x93, 0x04, 0xc6, 0xc4, 0xe1,
            0xbc, 0x9a, 0xc8, 0xf5, 0xb3, 0x7f, 0x83, 0xd6, 0x7f, 0x79, 0xc5, 0x35, 0xdc, 0x7f,
            0xac, 0x87, 0xca, 0xcd, 0x08, 0x80, 0x4a, 0x55, 0x60, 0x80, 0x09, 0xd3, 0x9b, 0x4a,
            0xc8, 0xe7, 0x7b, 0x4d, 0x5c, 0x82, 0x88, 0x24, 0xdf, 0x1c, 0xfd, 0xef, 0xb4, 0xbc,
            0xb7, 0x2f, 0x36, 0xf7, 0x2b, 0xb2, 0xcc, 0x14, 0x69, 0x63, 0xcc, 0x89, 0xd2, 0x74,
            0x3f, 0xd1, 0x98, 0x37, 0x0a, 0x35, 0x01, 0x28, 0x01, 0x18, 0x24, 0x02, 0x01, 0x36,
            0x03, 0x04, 0x02, 0x04, 0x01, 0x18, 0x30, 0x04, 0x14, 0x9c, 0xe7, 0xd9, 0xa8, 0x6b,
            0xf8, 0x71, 0xfa, 0x08, 0x10, 0xa3, 0xf2, 0x3a, 0x95, 0x30, 0xb1, 0x9e, 0xae, 0xc4,
            0x2c, 0x30, 0x05, 0x14, 0xdf, 0xfb, 0x79, 0xf1, 0x2b, 0xbf, 0x68, 0x18, 0x59, 0x7f,
            0xf7, 0xe8, 0xaf, 0x88, 0x91, 0x1c, 0x72, 0x32, 0xf7, 0x52, 0x18, 0x30, 0x0b, 0x40,
            0xcf, 0x01, 0x37, 0x65, 0xd6, 0x8a, 0xca, 0xd8, 0x33, 0x9f, 0x0f, 0x4f, 0xd5, 0xed,
            0x48, 0x42, 0x91, 0xca, 0xab, 0xf7, 0xae, 0xe1, 0x3b, 0x2b, 0xef, 0x9f, 0x43, 0x5a,
            0x96, 0xe0, 0xa5, 0x38, 0x8e, 0x39, 0xd0, 0x20, 0x8a, 0x0c, 0x92, 0x2b, 0x21, 0x7d,
            0xf5, 0x6c, 0x1d, 0x65, 0x6c, 0x0f, 0xd1, 0xe8, 0x55, 0x14, 0x5e, 0x27, 0xfd, 0xa4,
            0xac, 0xf9, 0x93, 0xdb, 0x29, 0x49, 0xaa, 0x71, 0x18,
        ];

        let test_output1 = [
            0x30, 0x82, 0x01, 0x80, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x00, 0x30, 0x0a,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x44, 0x31, 0x20,
            0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x01, 0x04,
            0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0xa2, 0x7c, 0x01, 0x05, 0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33, 0x30, 0x1e, 0x17, 0x0d,
            0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17,
            0x0d, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
            0xa2, 0x7c, 0x01, 0x03, 0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a,
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x01, 0x05, 0x0c, 0x10, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33,
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x69,
            0xda, 0xe9, 0x42, 0x88, 0xcf, 0x64, 0x94, 0x2d, 0xd5, 0x0a, 0x74, 0x2d, 0x50, 0xe8,
            0x5e, 0xbe, 0x15, 0x53, 0x24, 0xe5, 0xc5, 0x6b, 0xe5, 0x7f, 0xc1, 0x41, 0x11, 0x21,
            0xdd, 0x46, 0xa3, 0x0d, 0x63, 0xc3, 0xe3, 0x90, 0x7a, 0x69, 0x64, 0xdd, 0x66, 0x78,
            0x10, 0xa6, 0xc8, 0x0f, 0xfd, 0xb6, 0xf2, 0x9b, 0x88, 0x50, 0x93, 0x77, 0x9e, 0xf7,
            0xb4, 0xda, 0x94, 0x11, 0x33, 0x1e, 0xfe, 0xa3, 0x63, 0x30, 0x61, 0x30, 0x0f, 0x06,
            0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff,
            0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
            0x01, 0x06, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xdf,
            0xfb, 0x79, 0xf1, 0x2b, 0xbf, 0x68, 0x18, 0x59, 0x7f, 0xf7, 0xe8, 0xaf, 0x88, 0x91,
            0x1c, 0x72, 0x32, 0xf7, 0x52, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
            0x30, 0x16, 0x80, 0x14, 0xed, 0x31, 0x5e, 0x1a, 0xb7, 0xb9, 0x7a, 0xca, 0x04, 0x79,
            0x5d, 0x82, 0x57, 0x7a, 0xd7, 0x0a, 0x75, 0xd0, 0xdb, 0x7a,
        ];
        let test_output2 = [
            0x30, 0x82, 0x01, 0xa1, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x0a,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x44, 0x31, 0x20,
            0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x01, 0x03,
            0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x31, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04,
            0x01, 0x82, 0xa2, 0x7c, 0x01, 0x05, 0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33, 0x30, 0x1e, 0x17, 0x0d,
            0x32, 0x31, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a, 0x17,
            0x0d, 0x33, 0x30, 0x31, 0x32, 0x33, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x30, 0x44, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82,
            0xa2, 0x7c, 0x01, 0x01, 0x0c, 0x10, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x31, 0x42, 0x36, 0x36, 0x39, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x0a,
            0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x7c, 0x01, 0x05, 0x0c, 0x10, 0x30, 0x30,
            0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x33,
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x93,
            0x04, 0xc6, 0xc4, 0xe1, 0xbc, 0x9a, 0xc8, 0xf5, 0xb3, 0x7f, 0x83, 0xd6, 0x7f, 0x79,
            0xc5, 0x35, 0xdc, 0x7f, 0xac, 0x87, 0xca, 0xcd, 0x08, 0x80, 0x4a, 0x55, 0x60, 0x80,
            0x09, 0xd3, 0x9b, 0x4a, 0xc8, 0xe7, 0x7b, 0x4d, 0x5c, 0x82, 0x88, 0x24, 0xdf, 0x1c,
            0xfd, 0xef, 0xb4, 0xbc, 0xb7, 0x2f, 0x36, 0xf7, 0x2b, 0xb2, 0xcc, 0x14, 0x69, 0x63,
            0xcc, 0x89, 0xd2, 0x74, 0x3f, 0xd1, 0x98, 0xa3, 0x81, 0x83, 0x30, 0x81, 0x80, 0x30,
            0x0c, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30,
            0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07,
            0x80, 0x30, 0x20, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x01, 0x01, 0xff, 0x04, 0x16, 0x30,
            0x14, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2b,
            0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e,
            0x04, 0x16, 0x04, 0x14, 0x9c, 0xe7, 0xd9, 0xa8, 0x6b, 0xf8, 0x71, 0xfa, 0x08, 0x10,
            0xa3, 0xf2, 0x3a, 0x95, 0x30, 0xb1, 0x9e, 0xae, 0xc4, 0x2c, 0x30, 0x1f, 0x06, 0x03,
            0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xdf, 0xfb, 0x79, 0xf1, 0x2b,
            0xbf, 0x68, 0x18, 0x59, 0x7f, 0xf7, 0xe8, 0xaf, 0x88, 0x91, 0x1c, 0x72, 0x32, 0xf7,
            0x52,
        ];

        {
            let mut asn1_buf = [0u8; 1000];
            let mut w = ASN1Writer::new(&mut asn1_buf);
            decode_cert(&test_input1, &mut w).unwrap();
            assert_eq!(&test_output1, w.as_slice());
        }

        {
            let mut asn1_buf = [0u8; 1000];
            let mut w = ASN1Writer::new(&mut asn1_buf);
            decode_cert(&test_input2, &mut w).unwrap();
            assert_eq!(&test_output2, w.as_slice());
        }
    }
}
