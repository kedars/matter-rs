use crate::{
    error::Error,
    tlv::{self, TLVContainerIterator, TLVElement},
    tlv_common::TagType,
};
use chrono::{TimeZone, Utc};
use log::error;
use num_derive::FromPrimitive;

const OID_PUB_KEY_ECPUBKEY: [u8; 7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_EC_TYPE_PRIME256V1: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_WITH_SHA256: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];

const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x0F];
const OID_EXT_KEY_USAGE: [u8; 3] = [0x55, 0x1D, 0x25];
const OID_SUBJ_KEY_IDENTIFIER: [u8; 3] = [0x55, 0x1D, 0x0E];
const OID_AUTH_KEY_ID: [u8; 3] = [0x55, 0x1D, 0x23];

const OID_CLIENT_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const OID_SERVER_AUTH: [u8; 8] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

const OID_MATTER_NODE_ID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x01];
const OID_MATTER_FW_SIGN_ID: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x02];
const OID_MATTER_ICA_ID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x03];
const OID_MATTER_ROOT_CA_ID: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x04];
const OID_MATTER_FABRIC_ID: [u8; 10] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x05];
const OID_MATTER_NOC_CAT_ID: [u8; 10] =
    [0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0xA2, 0x7C, 0x01, 0x06];

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
pub fn decode_key_usage(t: TLVElement) -> Result<(), Error> {
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

pub fn decode_extended_key_usage(t: TLVElement) -> Result<(), Error> {
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

pub fn decode_basic_constraints(t: TLVElement, w: &mut dyn CertConsumer) -> Result<(), Error> {
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
    Ok(())
}

pub fn decode_extension_start(
    tag: &str,
    oid: &[u8],
    w: &mut dyn CertConsumer,
) -> Result<(), Error> {
    w.start_seq(tag)?;
    w.oid("", oid)?;
    w.bool("critical:", true)?;
    w.start_compound_str("value:")?;
    w.start_seq("")
}

pub fn decode_extension_end(w: &mut dyn CertConsumer) -> Result<(), Error> {
    w.end_seq()?;
    w.end_compound_str()?;
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
    w.start_ctx("X509v3 extensions:", 3)?;
    w.start_seq("")?;
    let iter = t.confirm_list()?.iter().ok_or(Error::Invalid)?;
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                ExtTags::BasicConstraints => {
                    decode_extension_start("X509v3 Basic Constraints", &OID_BASIC_CONSTRAINTS, w)?;
                    decode_basic_constraints(t, w)?;
                    decode_extension_end(w)?;
                }
                ExtTags::KeyUsage => decode_key_usage(t)?,
                ExtTags::ExtKeyUsage => decode_extended_key_usage(t)?,
                ExtTags::SubjectKeyId => println!("    Subject Key Id: {:x?}", t.get_slice()?),
                ExtTags::AuthKeyId => println!("    Authority Key Id: {:x?}", t.get_slice()?),
                ExtTags::FutureExt => println!("    Future Extensions: {:x?}", t.get_slice()?),
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
                    w.utf8str("", format!("{:016x}", t.get_u32()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::FirmwareSignId => {
                    w.start_seq("")?;
                    w.oid("Chip Firmware Signing Id:", &OID_MATTER_FW_SIGN_ID)?;
                    w.utf8str("", format!("{:016x}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::IcaId => {
                    w.start_seq("")?;
                    w.oid("Chip ICA Id:", &OID_MATTER_ICA_ID)?;
                    w.utf8str("", format!("{:016x}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::RootCaId => {
                    w.start_seq("")?;
                    w.oid("Chip Root CA Id:", &OID_MATTER_ROOT_CA_ID)?;
                    w.utf8str("", format!("{:016x}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::FabricId => {
                    w.start_seq("")?;
                    w.oid("Chip Fabric Id:", &OID_MATTER_FABRIC_ID)?;
                    w.utf8str("", format!("{:016x}", t.get_u8()?).as_str())?;
                    w.end_seq()?;
                }
                DnTags::NocCat => {
                    w.start_seq("")?;
                    w.oid("Chip NOC CAT Id:", &OID_MATTER_NOC_CAT_ID)?;
                    w.utf8str("", format!("{:08x}", t.get_u8()?).as_str())?;
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
    w.end_seq()?;

    current = get_next_tag(&mut iter, CertTags::EcPubKey)?;
    w.str("Public-Key:", current.get_slice()?)?;

    current = get_next_tag(&mut iter, CertTags::Extensions)?;
    decode_extensions(current, w)?;

    println!("After decode extensions");
    for t in iter {
        if let TagType::Context(tag) = t.get_tag() {
            let tag = num::FromPrimitive::from_u8(tag).ok_or(Error::InvalidData)?;
            match tag {
                CertTags::SerialNum => {}
                CertTags::SignAlgo => {}
                CertTags::Issuer => {}
                CertTags::NotBefore => {}
                CertTags::NotAfter => {}
                CertTags::Subject => {}
                CertTags::PubKeyAlgo => {}
                CertTags::EcCurveId => {}
                CertTags::EcPubKey => {}
                CertTags::Extensions => {}
                CertTags::Signature => println!("Signature: {:x?}", t.get_slice()?),
            }
        }
    }
    w.end_seq()?;
    println!("After final end_seq");
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

pub trait CertConsumer {
    fn start_seq(&mut self, tag: &str) -> Result<(), Error>;
    fn end_seq(&mut self) -> Result<(), Error>;
    fn integer(&mut self, tag: &str, i: &[u8]) -> Result<(), Error>;
    fn utf8str(&mut self, tag: &str, s: &str) -> Result<(), Error>;
    fn str(&mut self, tag: &str, s: &[u8]) -> Result<(), Error>;
    fn start_compound_str(&mut self, tag: &str) -> Result<(), Error>;
    fn end_compound_str(&mut self) -> Result<(), Error>;
    fn bool(&mut self, tag: &str, b: bool) -> Result<(), Error>;
    fn start_set(&mut self, tag: &str) -> Result<(), Error>;
    fn end_set(&mut self) -> Result<(), Error>;
    fn start_ctx(&mut self, tag: &str, val: u8) -> Result<(), Error>;
    fn end_ctx(&mut self) -> Result<(), Error>;
    fn oid(&mut self, tag: &str, oid: &[u8]) -> Result<(), Error>;
    fn utctime(&mut self, tag: &str, epoch: u32) -> Result<(), Error>;
}

pub struct CertPrinter {
    level: usize,
}

impl CertPrinter {
    pub fn new() -> Self {
        Self { level: 0 }
    }
}

const MAX_DEPTH: usize = 8;
const SPACE: [&str; MAX_DEPTH] = [
    "",
    "",
    "    ",
    "        ",
    "            ",
    "                ",
    "                    ",
    "                        ",
];

impl CertConsumer for CertPrinter {
    fn start_seq(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            println!("{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_seq(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn integer(&mut self, tag: &str, i: &[u8]) -> Result<(), Error> {
        println!("{} {} {:x?}", SPACE[self.level], tag, i);
        Ok(())
    }
    fn utf8str(&mut self, tag: &str, s: &str) -> Result<(), Error> {
        println!("{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn str(&mut self, tag: &str, s: &[u8]) -> Result<(), Error> {
        println!("{} {} {:x?}", SPACE[self.level], tag, s);
        Ok(())
    }
    fn start_compound_str(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            println!("{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_compound_str(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn bool(&mut self, tag: &str, b: bool) -> Result<(), Error> {
        println!("{} {} {}", SPACE[self.level], tag, b);
        Ok(())
    }
    fn start_set(&mut self, tag: &str) -> Result<(), Error> {
        if tag.len() != 0 {
            println!("{} {}", SPACE[self.level], tag);
        }
        self.level += 1;
        Ok(())
    }
    fn end_set(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn start_ctx(&mut self, tag: &str, val: u8) -> Result<(), Error> {
        println!("{} {} [{}]", SPACE[self.level], tag, val);
        self.level += 1;
        Ok(())
    }
    fn end_ctx(&mut self) -> Result<(), Error> {
        self.level -= 1;
        Ok(())
    }
    fn oid(&mut self, tag: &str, _oid: &[u8]) -> Result<(), Error> {
        println!("{} {}", SPACE[self.level], tag);
        Ok(())
    }

    fn utctime(&mut self, tag: &str, epoch: u32) -> Result<(), Error> {
        println!(
            "{} {} {}",
            SPACE[self.level],
            tag,
            Utc.timestamp(epoch as i64, 0)
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

    fn encode_len(&mut self, mut at_offset: usize, mut len: usize) -> Result<usize, Error> {
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

    fn str(&mut self, _tag: &str, s: &[u8]) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is BIT String
        self.write_str(0x03, s)
    }

    fn start_compound_str(&mut self, _tag: &str) -> Result<(), Error> {
        // Note: ASN1 has 3 string, this is Octet String
        self.add_compound(0x04)
    }

    fn end_compound_str(&mut self) -> Result<(), Error> {
        self.end_compound()
    }

    fn bool(&mut self, _tag: &str, b: bool) -> Result<(), Error> {
        Ok(())
    }

    fn start_set(&mut self, _tag: &str) -> Result<(), Error> {
        Ok(())
    }

    fn end_set(&mut self) -> Result<(), Error> {
        Ok(())
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
        let dt = Utc.timestamp(epoch as i64, 0);
        let time_str = format!("{}Z", dt.format("%y%m%d%H%M%S"));
        self.write_str(0x17, time_str.as_bytes())
    }
}

pub fn print_cert(buf: &[u8]) -> Result<(), Error> {
    let mut printer = CertPrinter::new();
    decode_cert(buf, &mut printer)?;

    println!("Test with ASN1 Writer");
    let mut asn1_buf = [0u8; 1000];
    let mut w = ASN1Writer::new(&mut asn1_buf);
    decode_cert(buf, &mut w)?;
    println!("After decode cert");
    let a = w.as_slice();
    for i in 0..a.len() {
        print!("{:02X}", a[i]);
    }

    Ok(())
}
