use std::sync::Arc;

use crate::{
    error::*,
    fabric::FabricMgr,
    mdns::{self, Mdns},
    secure_channel::{common::*, pake::PAKE},
    sys::SysMdnsService,
    transport::proto_demux::{self, ProtoCtx, ResponseRequired},
};
use log::{error, info};
use num;
use rand::prelude::*;

use super::case::Case;

/* Handle messages related to the Secure Channel
 */

pub struct SecureChannel {
    case: Case,
    pake: Option<(PAKE, SysMdnsService)>,
}

impl SecureChannel {
    pub fn new(fabric_mgr: Arc<FabricMgr>) -> SecureChannel {
        SecureChannel {
            pake: None,
            case: Case::new(fabric_mgr),
        }
    }

    pub fn open_comm_window(&mut self, salt: &[u8; 16], passwd: u32) -> Result<(), Error> {
        let name: u64 = rand::thread_rng().gen_range(0..0xFFFFFFFFFFFFFFFF);
        let name = format!("{:016X}", name);
        let mdns = Mdns::get()?.publish_service(&name, mdns::ServiceMode::Commissionable)?;
        self.pake = Some((PAKE::new(salt, passwd), mdns));
        Ok(())
    }

    pub fn close_comm_window(&mut self) {
        self.pake = None;
    }

    fn mrpstandaloneack_handler(&mut self, _ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In MRP StandAlone ACK Handler");
        Ok(ResponseRequired::No)
    }

    fn pbkdfparamreq_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PBKDF Param Request Handler");
        ctx.tx.set_proto_opcode(OpCode::PBKDFParamResponse as u8);
        if let Some((pake, _)) = &mut self.pake {
            pake.handle_pbkdfparamrequest(ctx)?;
        } else {
            error!("PASE Not enabled");
            create_sc_status_report(&mut ctx.tx, SCStatusCodes::InvalidParameter, None)?;
        }
        Ok(ResponseRequired::Yes)
    }

    fn pasepake1_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake1 Handler");
        ctx.tx.set_proto_opcode(OpCode::PASEPake2 as u8);
        if let Some((pake, _)) = &mut self.pake {
            pake.handle_pasepake1(ctx)?;
        } else {
            error!("PASE Not enabled");
            create_sc_status_report(&mut ctx.tx, SCStatusCodes::InvalidParameter, None)?;
        }
        Ok(ResponseRequired::Yes)
    }

    fn pasepake3_handler(&mut self, ctx: &mut ProtoCtx) -> Result<ResponseRequired, Error> {
        info!("In PASE Pake3 Handler");
        if let Some((pake, _)) = &mut self.pake {
            pake.handle_pasepake3(ctx)?;
            // TODO: Currently we assume that PAKE is not successful and reset the PAKE object
            self.pake = None;
        } else {
            error!("PASE Not enabled");
            create_sc_status_report(&mut ctx.tx, SCStatusCodes::InvalidParameter, None)?;
        }
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
