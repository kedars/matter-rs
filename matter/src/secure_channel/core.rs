use std::sync::Arc;

use crate::error::*;
use crate::fabric::FabricMgr;
use crate::proto_demux;
use crate::proto_demux::ResponseRequired;
use crate::proto_demux::{ProtoRx, ProtoTx};
use crate::secure_channel::{common::*, pake::PAKE};
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
    pub fn new(fabric_mgr: Arc<FabricMgr>) -> SecureChannel {
        SecureChannel {
            pake: PAKE::new(),
            case: Case::new(fabric_mgr),
        }
    }

    fn mrpstandaloneack_handler(
        &mut self,
        _proto_rx: &mut ProtoRx,
        _proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        proto_tx.proto_opcode = OpCode::PBKDFParamResponse as u8;
        self.pake.handle_pbkdfparamrequest(proto_rx, proto_tx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake1_handler(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake1 Handler");
        proto_tx.proto_opcode = OpCode::PASEPake2 as u8;
        self.pake.handle_pasepake1(proto_rx, proto_tx)?;
        Ok(ResponseRequired::Yes)
    }

    fn pasepake3_handler(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake3 Handler");
        self.pake.handle_pasepake3(proto_rx, proto_tx)?;
        Ok(ResponseRequired::Yes)
    }

    fn casesigma1_handler(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In CASE Sigma1 Handler");
        proto_tx.proto_opcode = OpCode::CASESigma2 as u8;
        self.case.handle_casesigma1(proto_rx, proto_tx)?;
        Ok(ResponseRequired::Yes)
    }
}

impl proto_demux::HandleProto for SecureChannel {
    fn handle_proto_id(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        let proto_opcode: OpCode =
            num::FromPrimitive::from_u8(proto_rx.proto_opcode).ok_or(Error::Invalid)?;
        proto_tx.proto_id = PROTO_ID_SECURE_CHANNEL;
        match proto_opcode {
            OpCode::MRPStandAloneAck => self.mrpstandaloneack_handler(proto_rx, proto_tx),
            OpCode::PBKDFParamRequest => self.pbkdfparamreq_handler(proto_rx, proto_tx),
            OpCode::PASEPake1 => self.pasepake1_handler(proto_rx, proto_tx),
            OpCode::PASEPake3 => self.pasepake3_handler(proto_rx, proto_tx),
            OpCode::CASESigma1 => self.casesigma1_handler(proto_rx, proto_tx),
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
