use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ProtoRx;
use crate::proto_demux::ResponseRequired;
use crate::secure_channel::{common::*, pake::PAKE};
use crate::transport::tx_ctx::TxCtx;
use log::{error, info};
use num;

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel {
    pake: PAKE,
}

impl Default for SecureChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureChannel {
    pub fn new() -> SecureChannel {
        SecureChannel { pake: PAKE::new() }
    }

    fn mrpstandaloneack_handler(
        &mut self,
        _proto_ctx: &mut ProtoRx,
        _tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(
        &mut self,
        proto_ctx: &mut ProtoRx,
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        tx_ctx.set_proto_opcode(OpCode::PBKDFParamResponse as u8);
        self.pake.handle_pbkdfparamrequest(proto_ctx, tx_ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake1_handler(
        &mut self,
        proto_ctx: &mut ProtoRx,
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake1 Handler");
        tx_ctx.set_proto_opcode(OpCode::PASEPake2 as u8);
        self.pake.handle_pasepake1(proto_ctx, tx_ctx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake3_handler(
        &mut self,
        proto_ctx: &mut ProtoRx,
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake3 Handler");
        self.pake.handle_pasepake3(proto_ctx, tx_ctx)?;
        Ok(ResponseRequired::Yes)
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(
        &mut self,
        proto_ctx: &mut ProtoRx,
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(proto_ctx.proto_opcode).ok_or(Error::Invalid)?;
        tx_ctx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
        match proto_opcode {
            OpCode::MRPStandAloneAck => self.mrpstandaloneack_handler(proto_ctx, tx_ctx),
            OpCode::PBKDFParamRequest => self.pbkdfparamreq_handler(proto_ctx, tx_ctx),
            OpCode::PASEPake1 => self.pasepake1_handler(proto_ctx, tx_ctx),
            OpCode::PASEPake3 => self.pasepake3_handler(proto_ctx, tx_ctx),
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
