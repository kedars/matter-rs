use crate::data_model::objects::*;
use crate::tlv_common::TagType;
use crate::{
    error::*,
    interaction_model::command::{self, CommandReq},
};
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
    let expiry_len = cmd_req
        .data
        .find_element(0)
        .ok_or(Error::Invalid)?
        .get_u8()
        .ok_or(Error::InvalidData)?;
    let bread_crumb = cmd_req
        .data
        .find_element(1)
        .ok_or(Error::Invalid)?
        .get_u8()
        .ok_or(Error::InvalidData)?;

    info!(
        "Received expiry len: {} breadcrumb: {:x}",
        expiry_len, bread_crumb
    );

    command::put_invoke_response_ib_start(
        &mut cmd_req.resp,
        TagType::Anonymous,
        command::InvokeResponseType::Command,
    )?;
    command::put_cmd_path_ib(
        &mut cmd_req.resp,
        TagType::Context(command::COMMAND_DATA_PATH_TAG),
        0,
        CLUSTER_GENERAL_COMMISSIONING_ID,
        CMD_ARMFAILSAFE_RESPONSE_ID,
    )?;
    cmd_req
        .resp
        .put_start_struct(TagType::Context(command::COMMAND_DATA_DATA_TAG))?;
    cmd_req.resp.put_u8(TagType::Context(0), 0)?;
    cmd_req.resp.put_utf8(TagType::Context(1), b"")?;
    cmd_req.resp.put_end_container()?;
    command::put_invoke_response_ib_end(&mut cmd_req.resp)?;
    Ok(())
}

fn command_armfailsafe_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ARMFAILSAFE_ID, handle_command_armfailsafe)
}
pub fn cluster_general_commissioning_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_GENERAL_COMMISSIONING_ID)?;
    cluster.add_command(command_armfailsafe_new()?)?;
    Ok(cluster)
}
