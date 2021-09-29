use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
use crate::transport::session;
use crate::transport::packet;
use crate::transport::udp;
use crate::transport::packet::PacketParser;

use ccm::{Ccm, consts::{U16, U12}};
use ccm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use aes::Aes128;

pub struct ProtoMsgParser<'a> {
    sess_mgr: &'a mut session::SessionMgr,
}

impl<'a> ProtoMsgParser<'a> {
    pub fn new(sess_mgr: &'a mut session::SessionMgr) -> ProtoMsgParser {
        let mut proto_msg = ProtoMsgParser{sess_mgr};
        let mut parser = PacketParser::new(&mut proto_msg);
        let mut transport = udp::UdpListener::new(&mut parser);
        transport.start_daemon().unwrap();
        proto_msg
    }
}

impl<'a> packet::ConsumeProtoMsg for ProtoMsgParser<'a> {
    fn consume_proto_msg(&mut self, matter_msg: packet::MatterMsg, parsebuf: &mut ParseBuf) {
        // Find the current session
        println!("Session_msg: {:x?}", self.sess_mgr);
        println!("sess_id: {} and src_addr: {}", matter_msg.sess_id, matter_msg.src_addr.unwrap().ip());
        let session = self.sess_mgr.get(matter_msg.sess_id, matter_msg.src_addr.unwrap().ip());
        if session.is_none() {
            println!("Dropping packet, invalid session");
            return; 
        }
        let session = session.unwrap();
        // This will modify parsebuf to only point to the valid decrypted data
        let dec_result = decrypt_in_place(&matter_msg, parsebuf, &session.dec_key);
        if let Err(_) = dec_result {
            println!("Error in decryption");
            return;
        }
        let end_off = dec_result.unwrap();
        let read_off = parsebuf.read_off;

        // Let's actually now change parsebuf to only consider the decrypted data
        println!("Decrypted data: {:x?}", &parsebuf.buf[read_off..end_off]);
    }
}

// Values as per the Matter spec
const AAD_LEN: usize = 8;
const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

fn get_iv(matter_msg: &packet::MatterMsg, iv: &mut [u8]) -> Result<(), &'static str>{
    // The IV is the source address (64-bit) followed by the message counter (32-bit)
    let mut write_buf = WriteBuf::new(iv, IV_LEN);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u64(0)?;
    write_buf.le_u32(matter_msg.ctr)?;
    Ok(())
}

fn decrypt_in_place(matter_msg: &packet::MatterMsg,
                    parsebuf: &mut ParseBuf,
                    key: &[u8]) -> Result<usize, &'static str> {
    // AAD: the unencrypted header of this packet
    let mut aad: [u8; AAD_LEN] = [0; AAD_LEN];
    aad.copy_from_slice(&parsebuf.buf[0..parsebuf.read_off]);

    // Tag:the last TAG_LEN bytes of the packet
    let tag_start = parsebuf.buf.len() - TAG_LEN;
    let mut tag: [u8; TAG_LEN] = [0; TAG_LEN];
    tag.copy_from_slice(&parsebuf.buf[tag_start..]);
    
    // IV
    let mut iv: [u8; IV_LEN] = [0; IV_LEN];
    get_iv(&matter_msg, &mut iv[0..])?;

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
    match cipher.decrypt_in_place_detached(nonce, &aad, &mut cipher_text, &tag) {
        Ok(_) => return Ok(tag_start),
        Err(_) => return Err("AES Error"),
    }
}

