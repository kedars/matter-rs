// Node Operational Credentials Cluster
use crate::data_model::objects::*;
use crate::error::*;
use log::info;

const CLUSTER_OPERATIONAL_CREDENTIALS_ID: u32 = 0x003E;

const CMD_CSRREQUEST_ID: u16 = 0x04;

fn handle_command_csrrequest(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("Handling CSRRequest");

    let csr_nonce = cmd_req
        .data
        .find_element(0)
        .ok_or(Error::Invalid)?
        .get_slice()
        .ok_or(Error::InvalidData)?;
    info!("Received CSR Nonce:{:?}", csr_nonce);
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
