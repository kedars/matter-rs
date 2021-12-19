use crate::data_model::objects::*;
use crate::interaction_model::command::InvokeRespIb;
use crate::interaction_model::CmdPathIb;
use crate::tlv_common::TagType;
use crate::{error::*, interaction_model::command::CommandReq};
use log::info;

const CLUSTER_GENERAL_COMMISSIONING_ID: u32 = 0x0030;

const CMD_ARMFAILSAFE_ID: u16 = 0x00;
const CMD_ARMFAILSAFE_RESPONSE_ID: u16 = 0x01;
const CMD_SETREGULATORYCONFIG_ID: u16 = 0x02;
const CMD_SETREGULATORYCONFIG_RESPONSE_ID: u16 = 0x03;

const CMD_PATH_ARMFAILSAFE_RESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_GENERAL_COMMISSIONING_ID),
    command: CMD_ARMFAILSAFE_RESPONSE_ID,
};

const CMD_PATH_SETREGULATORY_RESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_GENERAL_COMMISSIONING_ID),
    command: CMD_SETREGULATORYCONFIG_RESPONSE_ID,
};

fn handle_command_armfailsafe(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("Handling ARM Fail Safe");
    // These data types don't match the spec
    let expiry_len = cmd_req.data.find_tag(0)?.get_u8()?;
    let bread_crumb = cmd_req.data.find_tag(1)?.get_u8()?;

    info!(
        "Received expiry len: {} breadcrumb: {:x}",
        expiry_len, bread_crumb
    );

    let invoke_resp = InvokeRespIb::Command(CMD_PATH_ARMFAILSAFE_RESPONSE, |t| {
        t.put_u8(TagType::Context(0), 0)?;
        t.put_utf8(TagType::Context(1), b"")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn handle_command_setregulatoryconfig(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("Handling Set Regulatory Config");
    // These data types don't match the spec
    let country_code = cmd_req.data.find_tag(1)?.get_slice()?;
    info!("Received country code: {:?}", country_code);

    let invoke_resp = InvokeRespIb::Command(CMD_PATH_SETREGULATORY_RESPONSE, |t| {
        t.put_u8(TagType::Context(0), 0)?;
        t.put_utf8(TagType::Context(1), b"")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn command_armfailsafe_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ARMFAILSAFE_ID, handle_command_armfailsafe)
}

fn command_setregulatoryconfig_new() -> Result<Box<Command>, Error> {
    Command::new(
        CMD_SETREGULATORYCONFIG_ID,
        handle_command_setregulatoryconfig,
    )
}

pub fn cluster_general_commissioning_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_GENERAL_COMMISSIONING_ID)?;
    cluster.add_command(command_armfailsafe_new()?)?;
    cluster.add_command(command_setregulatoryconfig_new()?)?;
    Ok(cluster)
}
