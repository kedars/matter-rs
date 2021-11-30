use crate::error::*;
use crate::transport::exchange::Exchange;
use crate::transport::session::Session;
use crate::transport::tx_ctx::TxCtx;

const MAX_PROTOCOLS: usize = 4;

pub enum ResponseRequired {
    Yes,
    No,
}
pub struct ProtoDemux {
    proto_id_handlers: [Option<Box<dyn HandleProto>>; MAX_PROTOCOLS],
}

pub struct ProtoCtx<'a> {
    pub proto_id: usize,
    pub proto_opcode: u8,
    pub buf: &'a [u8],
    pub session: &'a mut Session,
    pub exchange: &'a mut Exchange,
    pub new_session: Option<Session>,
}

impl<'a> ProtoCtx<'a> {
    pub fn new(
        proto_id: usize,
        proto_opcode: u8,
        session: &'a mut Session,
        exchange: &'a mut Exchange,
        buf: &'a [u8],
    ) -> Self {
        ProtoCtx {
            proto_id,
            proto_opcode,
            exchange,
            session,
            buf,
            new_session: None,
        }
    }
}

pub trait HandleProto {
    fn handle_proto_id(
        &mut self,
        proto_ctx: &mut ProtoCtx,
        tx_ctx: &mut TxCtx,
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
        proto_ctx: &mut ProtoCtx,
        tx_ctx: &mut TxCtx,
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
