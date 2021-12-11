// Node Operational Credentials Cluster
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::CommandReq;
use log::info;

const CLUSTER_OPERATIONAL_CREDENTIALS_ID: u32 = 0x003E;

const CMD_CSRREQUEST_ID: u16 = 0x04;

fn handle_command_csrrequest(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    match cmd_req.cmd_path_ib.command as u16 {
        CMD_CSRREQUEST_ID => info!("Handling CSRRequest"),
        _ => info!("Command not supported"),
    }
    info!("Received variable:");
    let mut iter = cmd_req.data.into_iter().ok_or(Error::Invalid)?;
    while let Some(a) = iter.next() {
        info!("{}", a)
    }

    Ok(())
}

fn command_csrrequest_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_CSRREQUEST_ID, handle_command_csrrequest)
}

pub fn cluster_operational_credentials_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_OPERATIONAL_CREDENTIALS_ID)?;
    cluster.add_command(command_csrrequest_new()?)?;
    Ok(cluster)
}
