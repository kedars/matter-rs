use crate::error::*;

const MAX_PROTOCOLS: usize = 4;

pub struct ProtoDemux<'a> {
    proto_id_handlers: [Option<&'a mut dyn HandleProto>; MAX_PROTOCOLS],
}

pub trait HandleProto {
    fn handle_proto_id(&mut self, proto_id: u8, buf: &[u8]) -> Result<(), Error>;
    fn get_proto_id(& self) -> usize;
}

impl<'a> ProtoDemux<'a> {
    pub fn new() -> ProtoDemux<'a> {
        ProtoDemux{proto_id_handlers: [None, None, None, None]}
    }

    pub fn register(&mut self, proto_id_handle: &'a mut dyn HandleProto) -> Result<(), Error> {
        let proto_id = proto_id_handle.get_proto_id();
        self.proto_id_handlers[proto_id] = Some(proto_id_handle);
        Ok(())
    }

    pub fn handle(&mut self, proto_id: usize, proto_opcode: u8, buf: &[u8]) -> Result<(), Error> {
        if proto_id >= MAX_PROTOCOLS {
            return Err(Error::Invalid);
        }
        return self.proto_id_handlers[proto_id]
                .as_mut().ok_or(Error::NoHandler)?.handle_proto_id(proto_opcode, buf);
    }
}
