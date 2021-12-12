use super::objects::*;
use crate::{error::*, interaction_model::command, tlv_common::TagType};
use log::info;

const CLUSTER_ONOFF_ID: u32 = 0x0006;

const ATTR_ON_OFF_ID: u32 = 0x0;

const CMD_OFF_ID: u16 = 0x00;
const CMD_ON_ID: u16 = 0x01;
const CMD_TOGGLE_ID: u16 = 0x02;

fn attr_on_off_new() -> Result<Box<Attribute>, Error> {
    // Id: 0, Value: false
    Attribute::new(ATTR_ON_OFF_ID, AttrValue::Bool(false))
}

fn handle_command_on_off(_cluster: &mut Cluster, cmd_req: &mut CommandReq) -> Result<(), Error> {
    match cmd_req.command as u16 {
        CMD_OFF_ID => info!("Handling off"),
        CMD_ON_ID => info!("Handling on"),
        CMD_TOGGLE_ID => info!("Handling toggle"),
        _ => info!("Command not supported"),
    }

    // TODO: This whole this is completely mismatched with the spec. But it is what the chip-tool
    // expects, so...
    command::put_cmd_status_ib_start(&mut cmd_req.resp)?;
    command::put_cmd_path_ib(&mut cmd_req.resp, TagType::Context, 0, 0, 49, 2)?;
    command::put_status_ib(&mut cmd_req.resp, TagType::Context, 2, 0)?;
    command::put_cmd_status_ib_end(&mut cmd_req.resp)?;
    // Always mark complete for now
    cmd_req.trans.complete();
    Ok(())
}

fn command_on_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ON_ID, handle_command_on_off)
}

fn command_off_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_OFF_ID, handle_command_on_off)
}

fn command_toggle_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_TOGGLE_ID, handle_command_on_off)
}

pub fn cluster_on_off_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_ONOFF_ID)?;
    cluster.add_attribute(attr_on_off_new()?)?;
    cluster.add_command(command_on_new()?)?;
    cluster.add_command(command_off_new()?)?;
    cluster.add_command(command_toggle_new()?)?;
    Ok(cluster)
}
