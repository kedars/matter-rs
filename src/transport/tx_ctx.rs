use crate::error::*;
use crate::transport::enc_hdr;
use crate::transport::exchange;
use crate::transport::exchange::ExchangeRole;
use crate::transport::plain_hdr;
use crate::transport::mrp;
use crate::transport::session;
use crate::utils::WriteBuf;

// Keeping it conservative for now
const MAX_TX_BUF_SIZE: usize = 512;

pub struct TxCtx {
    _dst: Option<std::net::SocketAddr>,
    plain_hdr: plain_hdr::PlainHdr,
    enc_hdr: enc_hdr::EncHdr,
    pub buf: [u8; MAX_TX_BUF_SIZE],
}

impl TxCtx {
    pub fn new() -> TxCtx {
        TxCtx{_dst: None,
              plain_hdr: plain_hdr::PlainHdr::default(),
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
        self.enc_hdr.set_vendor(proto_vendor_id);
    }

    // Send the payload, exch_id is None for new exchange
    pub fn send(&mut self, session: &mut session::Session, exch_id: u16, role: exchange::ExchangeRole) -> Result<(), Error> {
        println!("payload: {:?}", self.buf);
        
        // Set up the parameters        
        self.enc_hdr.exch_id = exch_id;
        if role == ExchangeRole::Initiator { self.enc_hdr.set_initiator() }
        self.plain_hdr.sess_id = session.get_sess_id();
        self.plain_hdr.ctr = session.get_msg_ctr();
        self.plain_hdr.sess_type = plain_hdr::SessionType::Encrypted;

        // Get the exchange
        let mut exchange = session.get_exchange(exch_id, role, role == ExchangeRole::Initiator).ok_or(Error::Invalid)?;

        // Handle message reliability
        mrp::before_msg_send(&mut exchange, &mut self.plain_hdr, &mut self.enc_hdr)?;

        // Start with encrypted header
        Ok(())
    }
}

