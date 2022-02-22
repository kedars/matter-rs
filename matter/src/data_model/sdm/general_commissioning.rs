use crate::cmd_enter;
use crate::command_path_ib;
use crate::data_model::objects::*;
use crate::data_model::sdm::failsafe::FailSafe;
use crate::interaction_model::command::InvokeRespIb;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::{command_path, GenericPath};
use crate::tlv::TLVElement;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::{error::*, interaction_model::command::CommandReq};
use log::info;
use std::sync::Arc;

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum CommissioningError {
    Ok = 0,
    ErrValueOutsideRange = 1,
    ErrInvalidAuth = 2,
    ErrNotCommissioning = 3,
}

const CLUSTER_GENERAL_COMMISSIONING_ID: u32 = 0x0030;

const CMD_ARMFAILSAFE_ID: u16 = 0x00;
const CMD_ARMFAILSAFE_RESPONSE_ID: u16 = 0x01;
const CMD_SETREGULATORYCONFIG_ID: u16 = 0x02;
const CMD_SETREGULATORYCONFIG_RESPONSE_ID: u16 = 0x03;
const CMD_COMMISSIONING_COMPLETE_ID: u16 = 0x04;
const CMD_COMMISSIONING_COMPLETE_RESPONSE_ID: u16 = 0x05;

const CMD_PATH_ARMFAILSAFE_RESPONSE: command_path::Ib = command_path_ib!(
    0,
    CLUSTER_GENERAL_COMMISSIONING_ID,
    CMD_ARMFAILSAFE_RESPONSE_ID
);

const CMD_PATH_SETREGULATORY_RESPONSE: command_path::Ib = command_path_ib!(
    0,
    CLUSTER_GENERAL_COMMISSIONING_ID,
    CMD_SETREGULATORYCONFIG_RESPONSE_ID
);

const CMD_PATH_COMMISSIONING_COMPLETE_RESPONSE: command_path::Ib = command_path_ib!(
    0,
    CLUSTER_GENERAL_COMMISSIONING_ID,
    CMD_COMMISSIONING_COMPLETE_RESPONSE_ID
);

fn get_armfailsafe_params(data: &TLVElement) -> Result<(u8, u8), Error> {
    // These data types don't match the spec
    let expiry_len = data.find_tag(0)?.get_u8()?;
    let bread_crumb = data.find_tag(1)?.get_u8()?;

    info!(
        "Received expiry len: {} breadcrumb: {:x}",
        expiry_len, bread_crumb
    );
    Ok((expiry_len, bread_crumb))
}

pub struct GenCommCluster {
    failsafe: Arc<FailSafe>,
}

impl ClusterType for GenCommCluster {
    fn read_attribute(
        &self,
        _tag: TagType,
        _tw: &mut TLVWriter,
        _attr_id: u16,
    ) -> Result<(), Error> {
        // No custom attributes
        Ok(())
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);
        match cmd {
            Some(CMD_ARMFAILSAFE_ID) => self.handle_command_armfailsafe(cmd_req),
            Some(CMD_SETREGULATORYCONFIG_ID) => self.handle_command_setregulatoryconfig(cmd_req),
            Some(CMD_COMMISSIONING_COMPLETE_ID) => {
                self.handle_command_commissioningcomplete(cmd_req)
            }
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}

impl GenCommCluster {
    fn handle_command_armfailsafe(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("ARM Fail Safe");

        let (expiry_len, _) =
            get_armfailsafe_params(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;

        if self
            .failsafe
            .arm(expiry_len, cmd_req.trans.session.get_session_mode())
            .is_err()
        {
            return Err(IMStatusCode::Busy);
        }

        let invoke_resp = InvokeRespIb::CommandData(CMD_PATH_ARMFAILSAFE_RESPONSE, |t| {
            t.put_u8(TagType::Context(0), CommissioningError::Ok as u8)?;
            t.put_utf8(TagType::Context(1), b"")
        });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_setregulatoryconfig(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("Set Regulatory Config");
        // These data types don't match the spec
        let country_code = cmd_req
            .data
            .find_tag(1)
            .map_err(|_| IMStatusCode::InvalidCommand)?
            .get_slice()
            .map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received country code: {:?}", country_code);

        let invoke_resp = InvokeRespIb::CommandData(CMD_PATH_SETREGULATORY_RESPONSE, |t| {
            t.put_u8(TagType::Context(0), 0)?;
            t.put_utf8(TagType::Context(1), b"")
        });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_commissioningcomplete(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("Commissioning Complete");
        let mut status: u8 = CommissioningError::Ok as u8;

        // Has to be a Case Session
        if cmd_req.trans.session.get_local_fabric_idx().is_none() {
            status = CommissioningError::ErrInvalidAuth as u8;
        }

        // AddNOC or UpdateNOC must have happened, and that too for the same fabric
        // scope that is for this session
        if self
            .failsafe
            .disarm(cmd_req.trans.session.get_session_mode())
            .is_err()
        {
            status = CommissioningError::ErrInvalidAuth as u8;
        }

        let invoke_resp =
            InvokeRespIb::CommandData(CMD_PATH_COMMISSIONING_COMPLETE_RESPONSE, |t| {
                t.put_u8(TagType::Context(0), status)?;
                t.put_utf8(TagType::Context(1), b"")
            });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }
}

pub fn cluster_general_commissioning_new() -> Result<(Box<Cluster>, Arc<FailSafe>), Error> {
    let failsafe = Arc::new(FailSafe::new());
    let gen_cluster = Box::new(GenCommCluster {
        failsafe: failsafe.clone(),
    });

    let cluster = Cluster::new(CLUSTER_GENERAL_COMMISSIONING_ID, gen_cluster);

    Ok((cluster, failsafe))
}
