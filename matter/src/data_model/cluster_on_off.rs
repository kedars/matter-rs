use super::objects::*;
use crate::{
    cmd_enter,
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
};
use log::info;

const CLUSTER_ONOFF_ID: u32 = 0x0006;

const ATTR_ON_OFF_ID: u16 = 0x0;

const CMD_OFF_ID: u16 = 0x00;
const CMD_ON_ID: u16 = 0x01;
const CMD_TOGGLE_ID: u16 = 0x02;

fn attr_on_off_new() -> Result<Box<Attribute>, Error> {
    // Id: 0, Value: false
    Attribute::new(ATTR_ON_OFF_ID, AttrValue::Bool(false))
}

fn handle_command_on_off(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), IMStatusCode> {
    if let Some(cmd) = cmd_req.cmd.path.leaf {
        match cmd as u16 {
            CMD_OFF_ID => cmd_enter!("Off"),
            CMD_ON_ID => cmd_enter!("On"),
            CMD_TOGGLE_ID => cmd_enter!("Toggle"),
            _ => info!("Command not supported"),
        }
    }

    // Always mark complete for now
    cmd_req.trans.complete();
    Err(IMStatusCode::Sucess)
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
