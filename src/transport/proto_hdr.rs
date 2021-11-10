use std::fmt;

use crate::error::*;
use crate::transport::plain_hdr;
use crate::utils::parsebuf::ParseBuf;
use crate::utils::writebuf::WriteBuf;

use aes::Aes128;
use ccm::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use ccm::{
    consts::{U12, U16},
    Ccm,
};
use log::info;

const EXCHANGE_FLAG_VENDOR_MASK: u8 = 0x10;
const EXCHANGE_FLAG_SECEX_MASK: u8 = 0x08;
const EXCHANGE_FLAG_RELIABLE_MASK: u8 = 0x04;
const EXCHANGE_FLAG_ACK_MASK: u8 = 0x02;
const EXCHANGE_FLAG_INITIATOR_MASK: u8 = 0x01;

#[derive(Default)]
pub struct ProtoHdr {
    pub exch_id: u16,
    pub exch_flags: u8,
    pub proto_id: u16,
    pub proto_opcode: u8,
    pub proto_vendor_id: Option<u16>,
    pub ack_msg_ctr: Option<u32>,
}

impl ProtoHdr {
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

    pub fn decrypt_and_decode(
        &mut self,
        plain_hdr: &plain_hdr::PlainHdr,
        parsebuf: &mut ParseBuf,
        dec_key: Option<&[u8]>,
    ) -> Result<(), Error> {
        if let Some(d) = dec_key {
            // We decrypt only if the decryption key is valid
            decrypt_in_place(plain_hdr.ctr, parsebuf, d)?;
        }

        self.exch_flags = parsebuf.le_u8()?;
        self.proto_opcode = parsebuf.le_u8()?;
        self.exch_id = parsebuf.le_u16()?;
        self.proto_id = parsebuf.le_u16()?;

        info!("[decode] {} ", self);
        if self.is_vendor() {
            self.proto_vendor_id = Some(parsebuf.le_u16()?);
        }
        if self.is_ack() {
            self.ack_msg_ctr = Some(parsebuf.le_u32()?);
        }
        info!("[rx payload]: {:x?}", parsebuf.as_slice());
        Ok(())
    }

    pub fn encode(&mut self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        info!("[encode] {}", self);
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
        Ok(())
    }
}

impl fmt::Display for ProtoHdr {
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
        write!(
            f,
            "ExId: {}, Proto: {}, Opcode: {}, Flags: {}",
            self.exch_id, self.proto_id, self.proto_opcode, flag_str
        )
    }
}

// Values as per the Matter spec
const AAD_LEN: usize = 8;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

fn get_iv(recvd_ctr: u32, iv: &mut [u8]) -> Result<(), Error> {
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv, IV_LEN);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u64(0)?;
    write_buf.le_u32(recvd_ctr)?;
    Ok(())
}

pub fn encrypt_in_place(
    send_ctr: u32,
    plain_hdr: &[u8],
    writebuf: &mut WriteBuf,
    key: &[u8],
) -> Result<(), Error> {
    // IV
    let mut iv: [u8; IV_LEN] = [0; IV_LEN];
    get_iv(send_ctr, &mut iv)?;
    let nonce = GenericArray::from_slice(&iv);

    // Cipher Text
    let cipher_text = writebuf.as_mut_slice();

    type AesCcm = Ccm<Aes128, U16, U12>;
    let cipher = AesCcm::new(GenericArray::from_slice(key));
    let tag = cipher.encrypt_in_place_detached(nonce, plain_hdr, cipher_text)?;
    //println!("Tag: {:x?}", tag);
    //println!("Cipher Text: {:x?}", cipher_text);
    writebuf.append(tag.as_slice())?;

    Ok(())
}

fn decrypt_in_place(recvd_ctr: u32, parsebuf: &mut ParseBuf, key: &[u8]) -> Result<(), Error> {
    // AAD:
    //    the unencrypted header of this packet
    let mut aad: [u8; AAD_LEN] = [0; AAD_LEN];
    let parsed_slice = parsebuf.parsed_as_slice();
    if parsed_slice.len() == aad.len() {
        // The plain_header is variable sized in length, I wonder if the AAD is fixed at 8, or the variable size.
        // If so, we need to handle it cleanly here.
        aad.copy_from_slice(parsed_slice);
    } else {
        return Err(Error::InvalidAAD);
    }

    // Tag:
    //    the last TAG_LEN bytes of the packet
    let mut tag: [u8; TAG_LEN] = [0; TAG_LEN];
    tag.copy_from_slice(parsebuf.tail(TAG_LEN)?);
    let tag = GenericArray::from_slice(&tag);

    // IV:
    //   the specific way for creating IV is in get_iv
    let mut iv: [u8; IV_LEN] = [0; IV_LEN];
    get_iv(recvd_ctr, &mut iv)?;
    let nonce = GenericArray::from_slice(&iv);

    let cipher_text = parsebuf.as_slice();
    // println!("AAD: {:x?}", aad);
    // println!("Tag: {:x?}", tag);
    // println!("Cipher Text: {:x?}", cipher_text);
    // println!("IV: {:x?}", iv);

    // Matter Spec says Nonce size is 13, but the code has 12
    type AesCcm = Ccm<Aes128, U16, U12>;
    let cipher = AesCcm::new(GenericArray::from_slice(key));
    cipher.decrypt_in_place_detached(nonce, &aad, cipher_text, tag)?;

    Ok(())
}

pub const fn max_proto_hdr_len() -> usize {
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
        4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_decrypt_success() {
        // These values are captured from an execution run of the chip-tool binary
        let recvd_ctr = 41;
        let mut input_buf: [u8; 52] = [
            0x0, 0x11, 0x0, 0x0, 0x29, 0x0, 0x0, 0x0, 0xb7, 0xb0, 0xa0, 0xb2, 0xfb, 0xa9, 0x3b,
            0x66, 0x66, 0xb4, 0xec, 0xba, 0x4b, 0xa5, 0x3c, 0xfa, 0x0d, 0xe0, 0x04, 0xbb, 0xa6,
            0xa6, 0xfa, 0x04, 0x2c, 0xd0, 0xd4, 0x73, 0xd8, 0x41, 0x6a, 0xaa, 0x08, 0x5f, 0xe8,
            0xf7, 0x67, 0x8b, 0xfe, 0xaa, 0x43, 0xb1, 0x59, 0xe2,
        ];
        let input_buf_len = input_buf.len();
        let mut parsebuf = ParseBuf::new(&mut input_buf, input_buf_len);
        let key = [
            0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8,
            0x1b, 0x33,
        ];

        // decrypt_in_place() requires that the plain_text buffer of 8 bytes must be already parsed as AAD, we'll just fake it here
        parsebuf.le_u32().unwrap();
        parsebuf.le_u32().unwrap();

        decrypt_in_place(recvd_ctr, &mut parsebuf, &key).unwrap();
        assert_eq!(
            parsebuf.as_slice(),
            [
                5, 8, 0x58, 0x28, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01,
                0x24, 0x02, 0x06, 0x24, 0x03, 0x01, 0x18, 0x35, 0x01, 0x18, 0x18, 0x18, 0x18
            ]
        );
    }

    #[test]
    pub fn test_encrypt_success() {
        // These values are captured from an execution run of the chip-tool binary
        let send_ctr = 41;

        let mut main_buf: [u8; 52] = [0; 52];
        let main_buf_len = main_buf.len();
        let mut writebuf = WriteBuf::new(&mut main_buf, main_buf_len);

        let plain_hdr: [u8; 8] = [0x0, 0x11, 0x0, 0x0, 0x29, 0x0, 0x0, 0x0];

        let plain_text: [u8; 28] = [
            5, 8, 0x58, 0x28, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x01,
            0x24, 0x02, 0x06, 0x24, 0x03, 0x01, 0x18, 0x35, 0x01, 0x18, 0x18, 0x18, 0x18,
        ];
        writebuf.append(&plain_text).unwrap();

        let key = [
            0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8,
            0x1b, 0x33,
        ];

        encrypt_in_place(send_ctr, &plain_hdr, &mut writebuf, &key).unwrap();
        assert_eq!(
            writebuf.as_slice(),
            [
                0xb7, 0xb0, 0xa0, 0xb2, 0xfb, 0xa9, 0x3b, 0x66, 0x66, 0xb4, 0xec, 0xba, 0x4b, 0xa5,
                0x3c, 0xfa, 0x0d, 0xe0, 0x04, 0xbb, 0xa6, 0xa6, 0xfa, 0x04, 0x2c, 0xd0, 0xd4, 0x73,
                0xd8, 0x41, 0x6a, 0xaa, 0x08, 0x5f, 0xe8, 0xf7, 0x67, 0x8b, 0xfe, 0xaa, 0x43, 0xb1,
                0x59, 0xe2
            ]
        );
    }
}
