use crate::data_model::objects::*;
use crate::interaction_model::command::InvokeResponse;
use crate::interaction_model::CmdPathIb;
use crate::tlv_common::TagType;
use crate::{error::*, interaction_model::command::CommandReq};
use log::info;

const CLUSTER_GENERAL_COMMISSIONING_ID: u32 = 0x0030;

const CMD_ARMFAILSAFE_ID: u16 = 0x00;
const CMD_ARMFAILSAFE_RESPONSE_ID: u16 = 0x01;

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

    let invoke_resp = InvokeResponse::Command(
        CmdPathIb {
            endpoint: Some(0),
            cluster: Some(CLUSTER_GENERAL_COMMISSIONING_ID),
            command: CMD_ARMFAILSAFE_RESPONSE_ID,
        },
        |t| {
            t.put_u8(TagType::Context(0), 0)?;
            t.put_utf8(TagType::Context(1), b"")
        },
    );
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)
}

fn command_armfailsafe_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ARMFAILSAFE_ID, handle_command_armfailsafe)
}
pub fn cluster_general_commissioning_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_GENERAL_COMMISSIONING_ID)?;
    cluster.add_command(command_armfailsafe_new()?)?;
    Ok(cluster)
}
