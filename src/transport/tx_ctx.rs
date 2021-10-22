use crate::error::*;
use crate::transport::plain_hdr;
use crate::transport::enc_hdr;
use crate::transport::session;
use crate::utils::WriteBuf;

// Keeping it conservative for now
const MAX_TX_BUF_SIZE: usize = 512;

pub struct TxCtx {
    _dst: Option<std::net::SocketAddr>,
    _plain_hdr: plain_hdr::PlainHdr,
    enc_hdr: enc_hdr::EncHdr,
    pub buf: [u8; MAX_TX_BUF_SIZE],
}

impl TxCtx {
    pub fn new() -> TxCtx {
        TxCtx{_dst: None,
              _plain_hdr: plain_hdr::PlainHdr::default(),
              enc_hdr: enc_hdr::EncHdr::default(),
              buf: [0; MAX_TX_BUF_SIZE]
        }
    }

    pub fn get_payload_buf(&mut self) -> WriteBuf {
        let reserve = plain_hdr::max_plain_hdr_len() + enc_hdr::max_enc_hdr_len();
        let actual_len = self.buf.len() - reserve;
        WriteBuf::new(&mut self.buf[reserve..], actual_len)
    }

    pub fn set_proto_id(&mut self, proto_id: u16) {
        self.enc_hdr.proto_id = proto_id;
    }

    pub fn set_proto_opcode(&mut self, proto_opcode: u8) {
        self.enc_hdr.proto_opcode = proto_opcode;
    }

    pub fn set_proto_vendor_id(&mut self, proto_vendor_id: u16) {
        self.enc_hdr.proto_vendor_id = Some(proto_vendor_id);
    }

    // Send the payload, exch_id is None for new exchange
    pub fn send(&mut self, _session: &session::Session, _exch_id: Option<u16>) -> Result<(), Error> {
        println!("payload: {:?}", self.buf);
        Ok(())
    }
}

