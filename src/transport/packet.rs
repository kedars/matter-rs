use crate::transport::udp;
use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
    
pub struct PacketParser<'a> {
    dropped_pkts: u8,
    proto_consumer: &'a dyn ConsumeProtoMsg,
}

const SESSION_TYPE_MASK: u8 = 0x01;

#[derive(Debug)]
pub enum SessionType {
    None,
    Encrypted,
}

// This is the unencrypted message
pub struct MatterMsg {
    pub flags: u8,
    /* For the current spec that this is working against, the security flags have following structure:
     * bit 0: if 1, AES-CCM crypto is used for the packet
     * other bits seem to be reserved
     */
    pub sess_type: SessionType,
    pub sess_id: u16,
    pub ctr: u32,
    pub src_addr: Option<std::net::SocketAddr>,
}

impl<'a> PacketParser<'a> {
    pub fn new(proto_consumer: &'a dyn ConsumeProtoMsg) -> PacketParser<'a> {
        PacketParser {
            dropped_pkts: 0,
            proto_consumer,
        }
    }
}

pub trait ConsumeProtoMsg {
    fn consume_proto_msg(&self, matter_msg: MatterMsg, parsebuf: ParseBuf);
}

// The reason UDP is part of the name here is because, if message received on TCP
// it will have an additional 'message length' field first
fn parse_udp_hdr(msg: & mut ParseBuf) -> Result<MatterMsg, &'static str> {
    let mut flags    : u8 = 0;
    let mut sec_flags: u8 = 0;
    let mut sess_id  : u16 = 0;
    let mut ctr      : u32 = 0;

    msg.le_u8(&mut flags)?;
    msg.le_u8(&mut sec_flags)?;
    msg.le_u16(&mut sess_id)?;
    msg.le_u32(&mut ctr)?;

    let sess_type = if (sec_flags & SESSION_TYPE_MASK) == 1 { SessionType::Encrypted } else { SessionType::None };
    Ok(MatterMsg{flags, sess_type, sess_id, ctr, src_addr: None})
}

impl<'a> udp::ConsumeMsg for PacketParser<'a> {
    fn consume_message(&mut self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);

        let mut parsebuf = ParseBuf::new(msg, len);
        let matter_msg = match parse_udp_hdr(&mut parsebuf) {
            Ok(a) => a,
            Err(_) => { self.dropped_pkts += 1; return; }
        };

        println!("flags: {:x}", matter_msg.flags);
        println!("session type: {:#?}", matter_msg.sess_type);
        println!("sess_id: {}", matter_msg.sess_id);
        println!("ctr: {}", matter_msg.ctr);
        self.proto_consumer.consume_proto_msg(matter_msg, parsebuf);
    }
}


