use std::fmt;

use crate::error::*;
use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
use crate::transport::plain_hdr;

use aes::Aes128;
use ccm::{Ccm, consts::{U16, U12}};
use ccm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use log::info;

const EXCHANGE_FLAG_VENDOR_MASK:       u8 = 0x10;
const EXCHANGE_FLAG_SECEX_MASK:        u8 = 0x08;
const EXCHANGE_FLAG_RELIABLE_MASK:     u8 = 0x04;
const EXCHANGE_FLAG_ACK_MASK:          u8 = 0x02;
const EXCHANGE_FLAG_INITIATOR_MASK:    u8 = 0x01;

#[derive(Default)]
pub struct EncHdr {
    pub exch_id: u16,
    pub exch_flags: u8,
    pub proto_id: u16,
    pub proto_opcode: u8,
    pub proto_vendor_id: Option<u16>,
    pub ack_msg_ctr: Option<u32>,
}

impl EncHdr {
    pub fn is_vendor(&self) -> bool {
        (self.exch_flags & EXCHANGE_FLAG_VENDOR_MASK) != 0
    }
 
    pub fn set_vendor(&mut self, proto_vendor_id: u16) {
        self.exch_flags |= EXCHANGE_FLAG_RELIABLE_MASK;
        self.proto_vendor_id = Some(proto_vendor_id);
    }
    
    pub fn is_security_ext(&self) -> bool {
        (self.exch_flags & EXCHANGE_FLAG_SECEX_MASK) != 0
    }
    pub fn is_reliable(&self) -> bool {
        (self.exch_flags & EXCHANGE_FLAG_RELIABLE_MASK) != 0
    }

    pub fn set_reliable(&mut self) {
        self.exch_flags |= EXCHANGE_FLAG_RELIABLE_MASK;
    }
    
    pub fn is_ack(&self) -> bool {
        (self.exch_flags & EXCHANGE_FLAG_ACK_MASK) != 0
    }

    pub fn set_ack(&mut self, ack_msg_ctr: u32) {
        self.exch_flags |= EXCHANGE_FLAG_ACK_MASK;
        self.ack_msg_ctr = Some(ack_msg_ctr);
    }
    
    pub fn is_initiator(&self) -> bool {
        (self.exch_flags & EXCHANGE_FLAG_INITIATOR_MASK) != 0
    }
    
    pub fn set_initiator(&mut self) {
        self.exch_flags |= EXCHANGE_FLAG_INITIATOR_MASK;
    }

    pub fn decrypt_and_decode(&mut self, plain_hdr: &plain_hdr::PlainHdr, parsebuf: &mut ParseBuf, dec_key: &[u8]) -> Result<(), Error> {
        decrypt_in_place(&plain_hdr, parsebuf, dec_key)?;

        self.exch_flags   = parsebuf.le_u8()?;
        self.proto_opcode = parsebuf.le_u8()?;
        self.exch_id      = parsebuf.le_u16()?;
        self.proto_id     = parsebuf.le_u16()?;

        info!("[enc_hdr] {} ", self);
        if self.is_vendor() {
            self.proto_vendor_id = Some(parsebuf.le_u16()?);
        }
        if self.is_ack() {
            self.ack_msg_ctr = Some(parsebuf.le_u32()?);
        }
        info!("payload: {:x?}", &parsebuf.buf[parsebuf.read_off..(parsebuf.read_off + parsebuf.left)]);
        Ok(())
    }

    pub fn encode(&mut self, plain_hdr: &plain_hdr::PlainHdr, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        info!("[enc_hdr] {}", self);
        resp_buf.le_u8(self.exch_flags)?;
        resp_buf.le_u8(self.proto_opcode)?;
        resp_buf.le_u16(self.exch_id)?;
        resp_buf.le_u16(self.proto_id)?;
        if self.is_vendor() {
            resp_buf.le_u16(self.proto_vendor_id.ok_or(Error::Invalid)?)?;
        }
        if self.is_ack() {
            resp_buf.le_u32(self.ack_msg_ctr.ok_or(Error::Invalid)?)?;
        }
        // Perform encryption
        Ok(())
    }
}

impl fmt::Display for EncHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut flag_str: String = "".to_owned();
        if self.is_vendor() {
            flag_str.push_str("V|");
        }
        if self.is_security_ext() {
            flag_str.push_str("SX|");
        }
        if self.is_reliable() {
            flag_str.push_str("R|");
        }
        if self.is_ack() {
            flag_str.push_str("A|");
        }
        if self.is_initiator() {
            flag_str.push_str("I|");
        }
        write!(f, "ExId: {}, Proto: {}, Opcode: {}, Flags: {}", self.exch_id, self.proto_id, self.proto_opcode, flag_str)
    }
}

// Values as per the Matter spec
const AAD_LEN: usize = 8;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

fn get_iv(plain_hdr: &plain_hdr::PlainHdr, iv: &mut [u8]) -> Result<(), Error>{
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv, IV_LEN);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u64(0)?;
    write_buf.le_u32(plain_hdr.ctr)?;
    Ok(())
}

fn decrypt_in_place(plain_hdr: &plain_hdr::PlainHdr,
                    parsebuf: &mut ParseBuf,
                    key: &[u8]) -> Result<(), Error> {
    // AAD:
    //    the unencrypted header of this packet
    let mut aad: [u8; AAD_LEN] = [0; AAD_LEN];
    aad.copy_from_slice(&parsebuf.buf[0..parsebuf.read_off]);

    // Tag:
    //    the last TAG_LEN bytes of the packet
    let tag_start = parsebuf.read_off + parsebuf.left - TAG_LEN;
    let mut tag: [u8; TAG_LEN] = [0; TAG_LEN];
    tag.copy_from_slice(&parsebuf.buf[tag_start..]);
    let tag = GenericArray::from_slice(&tag);
    
    // IV:
    //   the specific way for creating IV is in get_iv
    let mut iv: [u8; IV_LEN] = [0; IV_LEN];
    get_iv(&plain_hdr, &mut iv[0..])?;
    let nonce = GenericArray::from_slice(&iv);

    let mut cipher_text = &mut parsebuf.buf[parsebuf.read_off..tag_start];
    //println!("AAD: {:x?}", aad);
    //println!("tag_start: {}", tag_start);
    //println!("Tag: {:x?}", &parsebuf.buf[tag_start..]);
    //println!("Cipher Text: {:x?}", cipher_text);
    //println!("IV: {:x?}", iv);

    // Matter Spec says Nonce size is 13, but the code has 12
    type AesCcm = Ccm<Aes128, U16, U12>;
    let cipher = AesCcm::new(GenericArray::from_slice(key));
    cipher.decrypt_in_place_detached(nonce, &aad, &mut cipher_text, &tag)?;

    // Truncate the parsebuf by TAG_LEN bytes
    parsebuf.truncate(TAG_LEN)?;
    Ok(())
}

pub const fn max_enc_hdr_len() -> usize {
    return
    // exchange flags
        1 +
    // protocol opcode
        1 +
    // exchange ID
        2 +
    // protocol ID
        2 +
    // [optional] protocol vendor ID
        2 +
    // [optional] acknowledged message counter
        4;
}
