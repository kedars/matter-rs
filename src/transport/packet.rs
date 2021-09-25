use crate::transport::udp;
use byteorder::{ByteOrder, LittleEndian};
    
pub struct PacketParser {
    dropped_pkts: u8,
}

// This is the unencrypted message
struct ChipMsg {
    flags: u8,
    sec_flags: u8,
    sess_id: u16,
    ctr: u32,
}

impl PacketParser {
    pub fn new() -> PacketParser {
        PacketParser {
            dropped_pkts: 0,
        }
    }

    // The reason UDP is part of the name here is because, if message received on TCP
    // it will have an additional 'message length' field first
    fn parse_udp_hdr<'b>(&self, msg: &'b mut ParseBuf<'b>) -> Result<ChipMsg, &'static str> {
        let mut flags    : u8 = 0;
        let mut sec_flags: u8 = 0;
        let mut sess_id  : u16 = 0;
        let mut ctr      : u32 = 0;

        msg.le_u8(&mut flags)?
            .le_u8(&mut sec_flags)?
            .le_u16(&mut sess_id)?
            .le_u32(&mut ctr)?;

        Ok(ChipMsg{flags, sec_flags, sess_id, ctr})
     }
}

impl udp::ConsumeMsg for PacketParser {
    fn consume_message(&mut self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);

        let mut msg = ParseBuf::new(msg);
        let chip_msg = match self.parse_udp_hdr(&mut msg) {
            Ok(a) => a,
            Err(_) => { self.dropped_pkts += 1; return; }
        };
        println!("flags: {:x}", chip_msg.flags);
        println!("security flags: {:x}", chip_msg.sec_flags);
        println!("sess_id: {}", chip_msg.sess_id);
        println!("ctr: {}", chip_msg.ctr);
    }

}

struct ParseBuf<'a> {
    buf: &'a[u8],
}

impl<'a> ParseBuf<'a> {
    pub fn new(buf: &'a [u8]) -> ParseBuf<'a> {
        ParseBuf{buf}
    }

    pub fn le_u8(&'a mut self, data: &mut u8) -> Result<&'a mut ParseBuf, &'static str> {
        // RustQ: Is there a better idiomatic way to do this in Rust? 
        if self.buf.len() > 1 {
            *data = self.buf[0];
            self.buf = &self.buf[1..];
            Ok(self)
        } else {
            return Err("Out of Bounds");
        }
    }

    pub fn le_u16(&'a mut self, data: &mut u16) -> Result<&'a mut ParseBuf, &'static str> {
        if self.buf.len() > 2 {
            *data = LittleEndian::read_u16(self.buf);
            self.buf = &self.buf[2..];
            Ok(self)
        } else {
            return Err("Out of Bounds");
        }

    }

    pub fn le_u32(&'a mut self, data: &mut u32) -> Result<&'a mut ParseBuf, &'static str> {
        if self.buf.len() > 4 {
            *data = LittleEndian::read_u32(self.buf);
            self.buf = &self.buf[4..];
            Ok(self)
        } else {
            return Err("Out of Bounds");
        }
    }
}

