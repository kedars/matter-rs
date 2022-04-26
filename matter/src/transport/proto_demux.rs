use std::net::SocketAddr;

use crate::error::*;
use crate::transport::exchange::Exchange;
use crate::transport::session::SessionHandle;

use super::packet::Packet;

const MAX_PROTOCOLS: usize = 4;

#[derive(PartialEq)]
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
    pub session: SessionHandle<'a>,
    pub exchange: &'a mut Exchange,
    pub peer: SocketAddr,
}

impl<'a> ProtoRx<'a> {
    pub fn new(
        proto_id: usize,
        proto_opcode: u8,
        session: SessionHandle<'a>,
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
        }
    }
}

pub trait HandleProto {
    fn handle_proto_id(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error>;

    fn get_proto_id(&self) -> usize;

    fn handle_session_event(&self) -> Result<(), Error> {
        Ok(())
    }
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
        tx_ctx: &mut Packet,
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
