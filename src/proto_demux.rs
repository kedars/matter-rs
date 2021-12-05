use std::net::SocketAddr;

use crate::error::*;
use crate::transport::exchange::Exchange;
use crate::transport::session::Session;
use crate::utils::writebuf::WriteBuf;

const MAX_PROTOCOLS: usize = 4;

pub enum ResponseRequired {
    Yes,
    No,
}
pub struct ProtoDemux {
    proto_id_handlers: [Option<Box<dyn HandleProto>>; MAX_PROTOCOLS],
}

pub struct ProtoRx<'a> {
    pub proto_id: usize,
    pub proto_opcode: u8,
    pub buf: &'a [u8],
    pub session: &'a mut Session,
    pub exchange: &'a mut Exchange,
    pub peer: SocketAddr,
    pub new_session: Option<Session>,
}

impl<'a> ProtoRx<'a> {
    pub fn new(
        proto_id: usize,
        proto_opcode: u8,
        session: &'a mut Session,
        exchange: &'a mut Exchange,
        peer: SocketAddr,
        buf: &'a [u8],
    ) -> Self {
        ProtoRx {
            proto_id,
            proto_opcode,
            exchange,
            session,
            buf,
            peer,
            new_session: None,
        }
    }
}

pub struct ProtoTx<'a> {
    pub proto_id: usize,
    pub proto_opcode: u8,
    pub write_buf: WriteBuf<'a>,
    pub session: Option<&'a mut Session>,
    pub exchange: Option<&'a mut Exchange>,
    pub peer: SocketAddr,
}

impl<'a> ProtoTx<'a> {
    pub fn new(buf: &'a mut [u8], peer: SocketAddr, hdr_reserve: usize) -> Result<Self, Error> {
        let mut p = ProtoTx {
            write_buf: WriteBuf::new(buf, buf.len()),
            peer,
            proto_id: 0,
            proto_opcode: 0,
            session: None,
            exchange: None,
        };
        p.write_buf.reserve(hdr_reserve)?;
        Ok(p)
    }
}

pub trait HandleProto {
    fn handle_proto_id(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error>;
    fn get_proto_id(&self) -> usize;
}

impl Default for ProtoDemux {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtoDemux {
    pub fn new() -> ProtoDemux {
        ProtoDemux {
            proto_id_handlers: [None, None, None, None],
        }
    }

    pub fn register(&mut self, proto_id_handle: Box<dyn HandleProto>) -> Result<(), Error> {
        let proto_id = proto_id_handle.get_proto_id();
        self.proto_id_handlers[proto_id] = Some(proto_id_handle);
        Ok(())
    }

    pub fn handle(
        &mut self,
        proto_ctx: &mut ProtoRx,
        tx_ctx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        if proto_ctx.proto_id >= MAX_PROTOCOLS {
            return Err(Error::Invalid);
        }
        return self.proto_id_handlers[proto_ctx.proto_id]
            .as_mut()
            .ok_or(Error::NoHandler)?
            .handle_proto_id(proto_ctx, tx_ctx);
    }
}
