use crate::utils::ParseBuf;
use crate::utils::WriteBuf;
use crate::transport::session;
use crate::transport::packet;
use crate::transport::udp;
use crate::transport::packet::PacketParser;

pub struct ProtoMsgParser<'a> {
    sess_mgr: &'a session::SessionMgr,
}

impl<'a> ProtoMsgParser<'a> {
    pub fn new(sess_mgr: &'a session::SessionMgr) -> ProtoMsgParser {
        let mut proto_msg = ProtoMsgParser{sess_mgr};
        let mut parser = PacketParser::new(&proto_msg);
        let mut transport = udp::UdpListener::new(&mut parser);
        transport.start_daemon().unwrap();
        proto_msg
    }
}

const TAG_LEN: usize = 16;
const IV_LEN: usize = 12;

impl<'a> packet::ConsumeProtoMsg for ProtoMsgParser<'a> {
    fn consume_proto_msg(&self, matter_msg: packet::MatterMsg, parsebuf: ParseBuf) {
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
        write_buf.le_u32(matter_msg.ctr);
        println!("IV: {:x?}", tmp_buffer);
    }
}
