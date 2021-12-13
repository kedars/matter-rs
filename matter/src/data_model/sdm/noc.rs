// Node Operational Credentials Cluster
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::command;
use crate::tlv_common::TagType;
use log::info;

const CLUSTER_OPERATIONAL_CREDENTIALS_ID: u32 = 0x003E;

const CMD_CSRREQUEST_ID: u16 = 0x04;
const CMD_CSRRESPONSE_ID: u16 = 0x05;

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

    // TODO: This whole thing is completely mismatched with the spec. But it is what the chip-tool
    // expects, so...
    command::put_cmd_status_ib_start(&mut cmd_req.resp, TagType::Anonymous, 0)?;
    command::put_cmd_path_ib(
        &mut cmd_req.resp,
        TagType::Context,
        command::COMMAND_DATA_PATH_TAG,
        0,
        CLUSTER_OPERATIONAL_CREDENTIALS_ID,
        CMD_CSRRESPONSE_ID,
    )?;
    cmd_req
        .resp
        .put_start_struct(TagType::Context, command::COMMAND_DATA_DATA_TAG)?;
    cmd_req
        .resp
        .put_str8(TagType::Context, 0, b"ThisistheNoCSRElementintheresponse")?;
    cmd_req
        .resp
        .put_str8(TagType::Context, 1, b"ThisistheAttestationSignature")?;
    cmd_req.resp.put_end_container()?;
    command::put_cmd_status_ib_end(&mut cmd_req.resp)?;
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
