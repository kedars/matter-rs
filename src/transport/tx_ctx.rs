use crate::error::*;
use crate::transport::exchange::ExchangeRole;
use crate::transport::mrp::ReliableMessage;
use crate::transport::plain_hdr;
use crate::transport::proto_hdr;
use crate::transport::session::SessionMgr;
use crate::utils::writebuf::*;

use log::trace;

pub struct TxCtx<'a> {
    plain_hdr: plain_hdr::PlainHdr,
    proto_hdr: proto_hdr::ProtoHdr,
    write_buf: WriteBuf<'a>,
}

impl<'a> TxCtx<'a> {
    pub fn new(buf: &'a mut [u8]) -> Result<TxCtx<'a>, Error> {
        let mut txctx = TxCtx {
            plain_hdr: plain_hdr::PlainHdr::default(),
            proto_hdr: proto_hdr::ProtoHdr::default(),
            write_buf: WriteBuf::new(buf, buf.len()),
        };
        txctx
            .write_buf
            .reserve(plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len())?;
        Ok(txctx)
    }

    pub fn get_write_buf(&mut self) -> &mut WriteBuf<'a> {
        &mut self.write_buf
    }

    pub fn set_proto_id(&mut self, proto_id: u16) {
        self.proto_hdr.proto_id = proto_id;
    }

    pub fn set_proto_opcode(&mut self, proto_opcode: u8) {
        self.proto_hdr.proto_opcode = proto_opcode;
    }

    pub fn set_proto_vendor_id(&mut self, proto_vendor_id: u16) {
        self.proto_hdr.set_vendor(proto_vendor_id);
    }

    pub fn as_slice(&self) -> &[u8] {
        self.write_buf.as_slice()
    }

    // Send the payload, exch_id is None for new exchange
    pub fn prepare_send(
        &mut self,
        rel_mgr: &mut ReliableMessage,
        sess_mgr: &mut SessionMgr,
        sess_index: usize,
        exch_index: usize,
    ) -> Result<(), Error> {
        trace!("payload: {:x?}", self.write_buf.as_slice());

        let session = sess_mgr.get_session(sess_index).ok_or(Error::NoSession)?;
        let exchange = session.get_exchange(exch_index).ok_or(Error::NoExchange)?;

        // Set up the parameters
        self.proto_hdr.exch_id = exchange.get_id();
        if exchange.get_role() == ExchangeRole::Initiator {
            self.proto_hdr.set_initiator()
        }
        self.plain_hdr.sess_id = session.get_peer_sess_id();
        self.plain_hdr.ctr = session.get_msg_ctr();
        if session.is_encrypted() {
            self.plain_hdr.sess_type = plain_hdr::SessionType::Encrypted;
        }

        // Handle message reliability
        rel_mgr.before_msg_send(
            sess_mgr,
            sess_index,
            exch_index,
            &self.plain_hdr,
            &mut self.proto_hdr,
        )?;

        // Generate encrypted header
        let mut tmp_buf: [u8; proto_hdr::max_proto_hdr_len()] = [0; proto_hdr::max_proto_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf[..], proto_hdr::max_proto_hdr_len());
        self.proto_hdr.encode(&mut write_buf)?;
        self.write_buf.prepend(write_buf.as_slice())?;

        // Generate plain-text header
        let mut tmp_buf: [u8; plain_hdr::max_plain_hdr_len()] = [0; plain_hdr::max_plain_hdr_len()];
        let mut write_buf = WriteBuf::new(&mut tmp_buf[..], plain_hdr::max_plain_hdr_len());
        self.plain_hdr.encode(&mut write_buf)?;
        let plain_hdr = write_buf.as_slice();

        trace!("unencrypted packet: {:x?}", self.write_buf.as_slice());
        let session = sess_mgr.get_session(sess_index).ok_or(Error::NoSession)?;
        let enc_key = session.get_enc_key();
        if let Some(e) = enc_key {
            proto_hdr::encrypt_in_place(self.plain_hdr.ctr, plain_hdr, &mut self.write_buf, e)?;
        }

        self.write_buf.prepend(plain_hdr)?;
        trace!("Full encrypted packet: {:x?}", self.write_buf.as_slice());

        Ok(())
    }
}
