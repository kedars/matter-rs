use crate::transport::udp;
use byteorder::{ByteOrder, LittleEndian};
    
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
    Ok(ChipMsg{flags, sess_type, sess_id, ctr})
}

impl udp::ConsumeMsg for PacketParser {
    fn consume_message(&mut self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);

        let mut parsebuf = ParseBuf::new(msg);
        let chip_msg = match parse_udp_hdr(&mut parsebuf) {
            Ok(a) => a,
            Err(_) => { self.dropped_pkts += 1; return; }
        };

        println!("flags: {:x}", chip_msg.flags);
        println!("session type: {:#?}", chip_msg.sess_type);
        println!("sess_id: {}", chip_msg.sess_id);
        println!("ctr: {}", chip_msg.ctr);
    }
}

struct ParseBuf<'a> {
    buf: &'a[u8],
    read_off: usize,
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a [u8]) -> ParseBuf<'a> {
        ParseBuf{buf: buf, read_off: 0}
    }

    pub fn le_u8(& mut self, data: &mut u8) -> Result<(), &'static str> {
        // RustQ: Is there a better idiomatic way to do this in Rust? 
        if self.buf.len() > 1 {
            *data = self.buf[self.read_off];
            self.read_off +=  1;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u16(& mut self, data: &mut u16) -> Result<(), &'static str> {
        if self.buf.len() > 2 {
            *data = LittleEndian::read_u16(&self.buf[self.read_off..]);
            self.read_off += 2;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }

    }

    pub fn le_u32(& mut self, data: &mut u32) -> Result<(), &'static str> {
        if self.buf.len() > 4 {
            *data = LittleEndian::read_u32(&self.buf[self.read_off..]);
            self.read_off += 4;
            Ok(())
        } else {
            return Err("Out of Bounds");
        }
    }
}

