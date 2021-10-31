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

pub struct TxCtx {
    _dst: Option<std::net::SocketAddr>,
    plain_hdr: plain_hdr::PlainHdr,
    enc_hdr: enc_hdr::EncHdr,
    pub buf: [u8; MAX_TX_BUF_SIZE],
    // The point before which any prepend will happen
    anchor: usize,
}

impl TxCtx {
    pub fn new() -> TxCtx {
        TxCtx{_dst: None,
              plain_hdr: plain_hdr::PlainHdr::default(),
              enc_hdr: enc_hdr::EncHdr::default(),
              buf: [0; MAX_TX_BUF_SIZE],
              anchor: 0,
        }
    }

    pub fn get_payload_buf(&mut self) -> WriteBuf {
        let reserve = plain_hdr::max_plain_hdr_len() + enc_hdr::max_enc_hdr_len();
        let actual_len = self.buf.len() - reserve;
        self.anchor  = reserve;
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

    pub fn prefix_hdr(&mut self, hdr: &[u8]) -> Result<(), Error> {
        // Append the encrypted header before the anchor
        let hdr_len = hdr.len();
        if hdr_len > self.anchor {
            return Err(Error::NoSpace);
        }

        let dst_slice = &mut self.buf[(self.anchor - hdr_len)..self.anchor];
        dst_slice.copy_from_slice(hdr);
        self.anchor -= hdr_len;
        Ok(())
    }

    // Send the payload, exch_id is None for new exchange
    pub fn send(&mut self, session: &mut session::Session, exch_id: u16, role: exchange::ExchangeRole) -> Result<(), Error> {
        info!("payload: {:x?}", self.buf);
        
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
        self.prefix_hdr(write_buf.as_slice())?;
        info!("enc_hdr: {:x?}", tmp_buf);

        let mut tmp_buf: [u8; plain_hdr::max_plain_hdr_len()] = [0; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf[..], plain_hdr::max_plain_hdr_len());
        self.plain_hdr.encode(&mut write_buf)?;
        self.prefix_hdr(write_buf.as_slice())?;
        info!("plain_hdr: {:x?}", tmp_buf);
        info!("Full unencrypted packet: {:x?}", &self.buf[self.anchor..]);
        Ok(())
    }
}

