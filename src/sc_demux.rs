use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ResponseRequired;
use crate::tlv::*;
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
    _dummy: u32,
}

impl SecureChannel {
    pub fn new() -> SecureChannel {
        SecureChannel { _dummy: 10 }
    }

    fn mrpstandaloneack_handler(
        &mut self,
        _opcode: OpCode,
        _buf: &[u8],
        _tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(
        &mut self,
        _opcode: OpCode,
        buf: &[u8],
        _tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        let root = get_root_node_struct(buf).ok_or(Error::InvalidData)?;

        let initiator_random_node = root.find_element(1).ok_or(Error::Invalid)?;
        let initiator_random = initiator_random_node
            .get_slice()
            .ok_or(Error::InvalidData)?;
        let initiator_sessid = root
            .find_element(2)
            .ok_or(Error::Invalid)?
            .get_u16()
            .ok_or(Error::Invalid)?;
        let passcode_id = root
            .find_element(3)
            .ok_or(Error::Invalid)?
            .get_u16()
            .ok_or(Error::Invalid)?;
        let has_params = root
            .find_element(4)
            .ok_or(Error::Invalid)?
            .get_bool()
            .ok_or(Error::Invalid)?;

        info!(
            "random: {:x?} sessid: {} passid: {} hasparams:{}",
            initiator_random, initiator_sessid, passcode_id, has_params
        );
        Ok(ResponseRequired::No)
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(
        &mut self,
        proto_opcode: u8,
        buf: &[u8],
        tx_ctx: &mut TxCtx,
    ) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(proto_opcode).ok_or(Error::Invalid)?;
        tx_ctx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
        match proto_opcode {
            OpCode::MRPStandAloneAck => {
                return self.mrpstandaloneack_handler(proto_opcode, buf, tx_ctx)
            }
            OpCode::PBKDFParamRequest => {
                return self.pbkdfparamreq_handler(proto_opcode, buf, tx_ctx)
            }
            _ => {
                error!("OpCode Not Handled: {:?}", proto_opcode);
                return Err(Error::InvalidOpcode);
            }
        }
    }

    fn get_proto_id(&self) -> usize {
        PROTO_ID_SECURE_CHANNEL as usize
    }
}
