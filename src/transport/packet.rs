use crate::transport::udp;
use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
    
pub struct PacketParser {
    dropped_pkts: u8,
}

const SESSION_TYPE_MASK: u8 = 0x01;

#[derive(Debug)]
pub enum SessionType {
    None,
    Encrypted,
}

// This is the unencrypted message
struct ChipMsg {
    flags: u8,
    /* For the current spec that this is working against, the security flags have following structure:
     * bit 0: if 1, AES-CCM crypto is used for the packet
     * other bits seem to be reserved
     */
    sess_type: SessionType,
    sess_id: u16,
    ctr: u32,
    src_addr: Option<std::net::SocketAddr>,
}

impl PacketParser {
    pub fn new() -> PacketParser {
        PacketParser {
            dropped_pkts: 0,
        }
    }

}

// The reason UDP is part of the name here is because, if message received on TCP
// it will have an additional 'message length' field first
fn parse_udp_hdr(msg: & mut ParseBuf) -> Result<ChipMsg, &'static str> {
    let mut flags    : u8 = 0;
    let mut sec_flags: u8 = 0;
    let mut sess_id  : u16 = 0;
    let mut ctr      : u32 = 0;

    msg.le_u8(&mut flags)?;
    msg.le_u8(&mut sec_flags)?;
    msg.le_u16(&mut sess_id)?;
    msg.le_u32(&mut ctr)?;

    let sess_type = if (sec_flags & SESSION_TYPE_MASK) == 1 { SessionType::Encrypted } else { SessionType::None };
    Ok(ChipMsg{flags, sess_type, sess_id, ctr, src_addr: None})
}

impl udp::ConsumeMsg for PacketParser {
    fn consume_message(&mut self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);

        let mut parsebuf = ParseBuf::new(msg, len);
        let chip_msg = match parse_udp_hdr(&mut parsebuf) {
            Ok(a) => a,
            Err(_) => { self.dropped_pkts += 1; return; }
        };

        println!("flags: {:x}", chip_msg.flags);
        println!("session type: {:#?}", chip_msg.sess_type);
        println!("sess_id: {}", chip_msg.sess_id);
        println!("ctr: {}", chip_msg.ctr);
        get_protocol_msg(parsebuf, chip_msg);
    }
}

const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;
// The sequence so far is msg (udp's view) -> ChipMsg (unencrypted) -> ProtocolMsg (encrypted)
fn get_protocol_msg (parsebuf: ParseBuf, chip_msg: ChipMsg) {
    let aad = &parsebuf.buf[0..parsebuf.read_off];
    println!("AAD: {:x?}", aad);
    let tag_start = parsebuf.buf.len() - TAG_LEN;
    println!("tag_start: {}, parsebuf len = {}", tag_start, parsebuf.buf.len());
    println!("Tag: {:x?}", &parsebuf.buf[tag_start..]);
    println!("Cipher Text: {:x?}", &parsebuf.buf[parsebuf.read_off..tag_start]);

    // Large enough for the IV
    let mut tmp_buffer: [u8; IV_LEN] = [0; IV_LEN];
    let mut write_buf = WriteBuf::new(&mut tmp_buffer, IV_LEN);
    // For some reason, this is 0 in the 'bypass' mode
    write_buf.le_u64(0);
    write_buf.le_u32(chip_msg.ctr);
    println!("IV: {:x?}", tmp_buffer);
    
}

