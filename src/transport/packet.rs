use crate::transport::udp;
use crate::utils::ParseBuf;
    
const SESSION_TYPE_MASK: u8 = 0x01;

#[derive(Debug)]
pub enum SessionType {
    None,
    Encrypted,
}

// We pass on the data to whoever implements this trait
pub trait ConsumeProtoMsg {
    fn consume_proto_msg(&mut self, matter_msg: MatterMsg, parsebuf: &mut ParseBuf);
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

pub struct PacketParser<'a> {
    dropped_pkts: u8,
    proto_consumer: &'a mut dyn ConsumeProtoMsg,
}

impl<'a> PacketParser<'a> {
    pub fn new(proto_consumer: &'a mut dyn ConsumeProtoMsg) -> PacketParser<'a> {
        PacketParser {
            dropped_pkts: 0,
            proto_consumer,
        }
    }
}

impl<'a> udp::ConsumeMsg for PacketParser<'a> {
    fn consume_message(&mut self, msg: &mut[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);

        let mut parsebuf = ParseBuf::new(msg, len);
        let mut matter_msg = match parse_udp_hdr(&mut parsebuf) {
            Ok(a) => a,
            Err(_) => { self.dropped_pkts += 1; return; }
        };
        matter_msg.src_addr = Some(src);

        println!("flags: {:x}", matter_msg.flags);
        println!("session type: {:#?}", matter_msg.sess_type);
        println!("sess_id: {}", matter_msg.sess_id);
        println!("ctr: {}", matter_msg.ctr);
        self.proto_consumer.consume_proto_msg(matter_msg, &mut parsebuf);
    }
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

