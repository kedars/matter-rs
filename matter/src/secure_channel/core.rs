use std::sync::Arc;

use crate::{
    error::*,
    fabric::FabricMgr,
    secure_channel::{common::*, pake::PAKE},
    transport::proto_demux::{self, ProtoCtx, ResponseRequired},
};
use log::{error, info};
use num;

use super::case::Case;

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel {
    case: Case,
    pake: PAKE,
}

impl SecureChannel {
    pub fn new(fabric_mgr: Arc<FabricMgr>, salt: &[u8; 16], passwd: u32) -> SecureChannel {
        SecureChannel {
            pake: PAKE::new(salt, passwd),
            case: Case::new(fabric_mgr),
        }
    }

    pub fn open_comm_window(&mut self) {
        self.pake.enable();
    }

    pub fn close_comm_window(&mut self) {
        self.pake.disable();
    }

    fn mrpstandaloneack_handler(&mut self, _ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        ctx.tx.set_proto_opcode(OpCode::PBKDFParamResponse as u8);
        self.pake.handle_pbkdfparamrequest(ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake1_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake1 Handler");
        ctx.tx.set_proto_opcode(OpCode::PASEPake2 as u8);
        self.pake.handle_pasepake1(ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake3_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake3 Handler");
        self.pake.handle_pasepake3(ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn casesigma1_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In CASE Sigma1 Handler");
        ctx.tx.set_proto_opcode(OpCode::CASESigma2 as u8);
        self.case.handle_casesigma1(ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn casesigma3_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In CASE Sigma3 Handler");
        self.case.handle_casesigma3(ctx)?;
        Ok(ResponseRequired::Yes)
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(ctx.rx.get_proto_opcode()).ok_or(Error::Invalid)?;
        ctx.tx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
        match proto_opcode {
            OpCode::MRPStandAloneAck => self.mrpstandaloneack_handler(ctx),
            OpCode::PBKDFParamRequest => self.pbkdfparamreq_handler(ctx),
            OpCode::PASEPake1 => self.pasepake1_handler(ctx),
            OpCode::PASEPake3 => self.pasepake3_handler(ctx),
            OpCode::CASESigma1 => self.casesigma1_handler(ctx),
            OpCode::CASESigma3 => self.casesigma3_handler(ctx),
            _ => {
                error!("OpCode Not Handled: {:?}", proto_opcode);
                Err(Error::InvalidOpcode)
            }
        }
    }

    fn get_proto_id(&self) -> usize {
        PROTO_ID_SECURE_CHANNEL as usize
    }
}
