use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ProtoCtx;
use crate::proto_demux::ResponseRequired;
use crate::secure_channel::pake::PAKE;
use crate::transport::tx_ctx::TxCtx;
use log::{error, info};
use num;
use num_derive::FromPrimitive;

/* Handle messages related to the Secure Channel
 */

/* Interaction Model ID as per the Matter Spec */
const PROTO_ID_SECURE_CHANNEL: usize = 0x00;

#[derive(FromPrimitive, Debug)]
enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
}

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
        _proto_ctx: &mut ProtoCtx,
        _tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(
        &mut self,
        proto_ctx: &mut ProtoCtx,
        _tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        self.pake.handle_pbkdfparamrequest(proto_ctx.buf)?;
        Ok(ResponseRequired::No)
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(
        &mut self,
        proto_ctx: &mut ProtoCtx,
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(proto_ctx.proto_opcode).ok_or(Error::Invalid)?;
        tx_ctx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
        match proto_opcode {
            OpCode::MRPStandAloneAck => self.mrpstandaloneack_handler(proto_ctx, tx_ctx),
            OpCode::PBKDFParamRequest => self.pbkdfparamreq_handler(proto_ctx, tx_ctx),
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
