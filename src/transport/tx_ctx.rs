use crate::error::*;
use crate::transport::enc_hdr;
use crate::transport::exchange;
use crate::transport::exchange::ExchangeRole;
use crate::transport::plain_hdr;
use crate::transport::mrp;
use crate::transport::session;
use crate::utils::WriteBuf;

use log::info;

// Keeping it conservative for now
const MAX_TX_BUF_SIZE: usize = 512;

pub struct TxCtx<'a> {
    _dst: Option<std::net::SocketAddr>,
    plain_hdr: plain_hdr::PlainHdr,
    enc_hdr: enc_hdr::EncHdr,
    pub write_buf: WriteBuf<'a>,
}

impl<'a> TxCtx<'a> {
    pub fn new(buf: &'a mut[u8]) -> TxCtx<'a> {
        let mut txctx = TxCtx{_dst: None,
              plain_hdr: plain_hdr::PlainHdr::default(),
              enc_hdr: enc_hdr::EncHdr::default(),
              write_buf: WriteBuf::new(buf, buf.len()),
        };
        txctx.write_buf.reserve(plain_hdr::max_plain_hdr_len() + enc_hdr::max_enc_hdr_len());
        txctx
    }

    pub fn get_write_buf(&mut self) -> &mut WriteBuf<'a> {
        &mut self.write_buf
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
        info!("payload: {:x?}", self.write_buf.as_slice());
        
        // Set up the parameters        
        self.enc_hdr.exch_id = exch_id;
        if role == ExchangeRole::Initiator { self.enc_hdr.set_initiator() }
        self.plain_hdr.sess_id = session.get_peer_sess_id();
        self.plain_hdr.ctr = session.get_msg_ctr();
        self.plain_hdr.sess_type = plain_hdr::SessionType::Encrypted;

        // Get the exchange
        let mut exchange = session.get_exchange(exch_id, role, role == ExchangeRole::Initiator).ok_or(Error::Invalid)?;

        // Handle message reliability
        mrp::before_msg_send(&mut exchange, &self.plain_hdr, &mut self.enc_hdr)?;

        // Generate encrypted header
        let mut tmp_buf: [u8; enc_hdr::max_enc_hdr_len()] = [0; enc_hdr::max_enc_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf[..], enc_hdr::max_enc_hdr_len());
        self.enc_hdr.encode(&self.plain_hdr, &mut write_buf)?;
        self.write_buf.prepend(write_buf.as_slice())?;
        info!("enc_hdr: {:x?}", tmp_buf);

        let mut tmp_buf: [u8; plain_hdr::max_plain_hdr_len()] = [0; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf[..], plain_hdr::max_plain_hdr_len());
        self.plain_hdr.encode(&mut write_buf)?;
        self.write_buf.prepend(write_buf.as_slice())?;
        info!("plain_hdr: {:x?}", tmp_buf);
        info!("Full unencrypted packet: {:x?}", self.write_buf.as_slice());
        Ok(())
    }
}

