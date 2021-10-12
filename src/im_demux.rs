use crate::error::*;
use crate::proto_demux;
use log::{error, info};
use num;
use num_derive::FromPrimitive;

/* Handle messages related to the Interation Model
 *
 * I am going to try doing this without an InteractionModel object, just to check what kind of complexity I incur/not-incur
 */


/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_INTERACTION_MODEL: usize = 0x01;

#[derive(FromPrimitive)]
enum OpCode {
    Reserved          = 0,
    StatusResponse    = 1,
    ReadRequest       = 2,
    SubscribeRequest  = 3,
    SubscriptResponse = 4,
    ReportData        = 5,
    WriteRequest      = 6,
    WriteResponse     = 7,
    InvokeRequest     = 8,
    InvokeResponse    = 9,
    TimedRequest      = 10,
}

pub trait HandleInteraction {
    fn handle_invoke_cmd(&mut self) -> Result<(), Error>;
}

pub struct InteractionModel<'a> {
    handler: &'a mut dyn HandleInteraction,
}

impl<'a> InteractionModel<'a> {
    pub fn init(handler: &'a mut dyn HandleInteraction) -> InteractionModel {
        InteractionModel{handler}
    }

    fn invoke_req_handler(&mut self, opcode: OpCode, buf: &[u8]) -> Result<(), Error> {
        info!("In invoke req handler");
        return self.handler.handle_invoke_cmd();
    }
}

impl <'a> proto_demux::HandleProto for InteractionModel<'a> {
    fn handle_proto_id(&mut self, proto_id: u8, buf: &[u8]) -> Result<(), Error> {
        let proto_id: OpCode = num::FromPrimitive::from_u8(proto_id).
            ok_or(Error::Invalid)?;
        match proto_id {
            OpCode::InvokeRequest => return self.invoke_req_handler(proto_id, buf),
            _ => {
                error!("Invalid Opcode");
                return Err(Error::InvalidOpcode);
            }
        }
    }

    fn get_proto_id(& self) -> usize {
        PROTO_ID_INTERACTION_MODEL as usize
    }
}


