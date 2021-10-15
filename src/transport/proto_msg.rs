use crate::error::*;
use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
use crate::transport::packet;

use aes::Aes128;
use ccm::{Ccm, consts::{U16, U12}};
use ccm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use log::{error, info};


const EXCHANGE_FLAG_VENDOR_MASK: u8 = 0xf0;
const EXCHANGE_FLAG_ACK_MASK:    u8 = 0x02;

pub fn parse_enc_hdr(plain_hdr: &packet::PlainHdr, parsebuf: &mut ParseBuf, dec_key: &[u8]) -> Result<(), Error> {
    let end_off = decrypt_in_place(&plain_hdr, parsebuf, dec_key)?;
    let read_off = parsebuf.read_off;

    // Let's actually now change parsebuf to only consider the decrypted data
    //println!("Decrypted data: {:x?}", &parsebuf.buf[read_off..end_off]);

    let mut ex_flags: u8 = 0;
    let mut proto_opcode: u8 = 0;
    let mut ex_id: u16 = 0;
    let mut proto_id: u16 = 0;
    let mut proto_vendor_id: u16 = 0;
    let mut ack_msg_ctr: u32 = 0;
    parsebuf.le_u8(&mut ex_flags)?;
    parsebuf.le_u8(&mut proto_opcode)?;
    parsebuf.le_u16(&mut ex_id)?;
    parsebuf.le_u16(&mut proto_id)?;
    println!("ex_flags: {:x?} \nproto_opcode: {} \nexchange ID: {} \nproto id: {}",
             ex_flags, proto_opcode, ex_id, proto_id);
    if (ex_flags & EXCHANGE_FLAG_VENDOR_MASK) == 1 {
        parsebuf.le_u16(&mut proto_vendor_id)?;
        println!("proto_vendor_id: {}", proto_vendor_id);
    }
    if (ex_flags & EXCHANGE_FLAG_ACK_MASK) == 1 {
        parsebuf.le_u32(&mut ack_msg_ctr)?;
        println!("ack msg ctr: {}", ack_msg_ctr);
    }
    println!("Payload: {:x?}", &parsebuf.buf[parsebuf.read_off..end_off]);
    Ok(())
}

// Values as per the Matter spec
const AAD_LEN: usize = 8;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

fn get_iv(plain_hdr: &packet::PlainHdr, iv: &mut [u8]) -> Result<(), Error>{
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv, IV_LEN);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u64(0)?;
    write_buf.le_u32(plain_hdr.ctr)?;
    Ok(())
}

fn decrypt_in_place(plain_hdr: &packet::PlainHdr,
                    parsebuf: &mut ParseBuf,
                    key: &[u8]) -> Result<usize, Error> {
    // AAD: the unencrypted header of this packet
    let mut aad: [u8; AAD_LEN] = [0; AAD_LEN];
    aad.copy_from_slice(&parsebuf.buf[0..parsebuf.read_off]);

    // Tag:the last TAG_LEN bytes of the packet
    let tag_start = parsebuf.buf.len() - TAG_LEN;
    let mut tag: [u8; TAG_LEN] = [0; TAG_LEN];
    tag.copy_from_slice(&parsebuf.buf[tag_start..]);
    
    // IV
    let mut iv: [u8; IV_LEN] = [0; IV_LEN];
    get_iv(&plain_hdr, &mut iv[0..])?;

    let mut cipher_text = &mut parsebuf.buf[parsebuf.read_off..tag_start];
    //println!("AAD: {:x?}", aad);
    //println!("tag_start: {}, parsebuf len = {}", tag_start, parsebuf.buf.len());
    //println!("Tag: {:x?}", &parsebuf.buf[tag_start..]);
    //println!("Cipher Text: {:x?}", cipher_text);
    //println!("IV: {:x?}", iv);

    // Matter Spec says Nonce size is 13, but the code has 12
    type AesCcm = Ccm<Aes128, U16, U12>;
    let cipher = AesCcm::new(GenericArray::from_slice(key));
    let nonce = GenericArray::from_slice(&iv);
    let tag = GenericArray::from_slice(&tag);
    cipher.decrypt_in_place_detached(nonce, &aad, &mut cipher_text, &tag)?;
    Ok(tag_start)
}

