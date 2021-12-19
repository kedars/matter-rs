// Node Operational Credentials Cluster
use crate::data_model::objects::*;
use crate::interaction_model::command::{self, CommandReq, InvokeResponse};
use crate::interaction_model::CmdPathIb;
use crate::pki::pki::{self, KeyPair};
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::utils::writebuf::WriteBuf;
use crate::{cert, error::*};
use log::{error, info};

// Some placeholder value for now
const MAX_CSR_LEN: usize = 300;
// As defined in the Matter Spec
const RESP_MAX: usize = 900;

const CLUSTER_OPERATIONAL_CREDENTIALS_ID: u32 = 0x003E;

const CMD_CSRREQUEST_ID: u16 = 0x04;
const CMD_CSRRESPONSE_ID: u16 = 0x05;
const CMD_ADDNOC_ID: u16 = 0x06;
const CMD_NOCRESPONSE_ID: u16 = 0x08;
const CMD_ADDTRUSTEDROOTCERT_ID: u16 = 0x0b;

const CMD_PATH_CSRRESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_OPERATIONAL_CREDENTIALS_ID),
    command: CMD_CSRRESPONSE_ID,
};

const CMD_PATH_NOCRESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_OPERATIONAL_CREDENTIALS_ID),
    command: CMD_NOCRESPONSE_ID,
};

fn add_nocsrelement(
    noc_keypair: &KeyPair,
    csr_nonce: &[u8],
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let mut csr: [u8; MAX_CSR_LEN] = [0; MAX_CSR_LEN];
    let len = noc_keypair.get_csr(&mut csr)?;
    let csr = &csr[0..len];
    let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
    let mut write_buf = WriteBuf::new(&mut buf, RESP_MAX);
    let mut writer = TLVWriter::new(&mut write_buf);
    writer.put_start_struct(TagType::Anonymous)?;
    writer.put_str8(TagType::Context(1), csr)?;
    writer.put_str8(TagType::Context(2), csr_nonce)?;
    writer.put_end_container()?;

    resp.put_str8(TagType::Context(0), write_buf.as_slice())?;
    Ok(())
}

fn handle_command_csrrequest(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("Handling CSRRequest");

    let csr_nonce = cmd_req.data.find_tag(0)?.get_slice()?;
    info!("Received CSR Nonce:{:?}", csr_nonce);

    let noc_keypair = pki::KeyPair::new()?;

    let invoke_resp = InvokeResponse::Command(CMD_PATH_CSRRESPONSE, |t| {
        add_nocsrelement(&noc_keypair, csr_nonce, t)?;
        t.put_str8(TagType::Context(1), b"ThisistheAttestationSignature")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)
}

fn handle_command_addtrustedrootcert(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("Handling AddTrustedRootCert");

    let root_cert = cmd_req.data.find_tag(0)?.get_slice()?;
    info!("Received Trusted Cert:{:?}", root_cert);

    let invoke_resp = InvokeResponse::Status(cmd_req.to_cmd_path_ib(), 0, 0, command::dummy);
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)
}

fn get_addnoc_params<'a, 'b, 'c>(
    cmd_req: &mut CommandReq<'a, 'b, 'c>,
) -> Result<(&'a [u8], &'a [u8], &'a [u8], u32, u16), Error> {
    let noc_value = cmd_req.data.find_tag(0)?.get_slice()?;
    let icac_value = cmd_req.data.find_tag(1)?.get_slice()?;
    let ipk_value = cmd_req.data.find_tag(2)?.get_slice()?;
    let case_admin_node_id = cmd_req.data.find_tag(3)?.get_u32()?;
    let vendor_id = cmd_req.data.find_tag(4)?.get_u16()?;
    Ok((
        noc_value,
        icac_value,
        ipk_value,
        case_admin_node_id,
        vendor_id,
    ))
}

fn handle_command_addnoc(_cluster: &mut Cluster, cmd_req: &mut CommandReq) -> Result<(), Error> {
    info!("Handling AddNOC");
    let (noc_value, icac_value, _ipk_value, _case_admin_node_id, _vendor_id) =
        get_addnoc_params(cmd_req)?;

    info!("Received NOC as:");
    cert::print_cert(&noc_value).map_err(|e| {
        error!("Error parsing NOC");
        e
    })?;

    info!("Received ICAC as:");
    let _ = cert::print_cert(&icac_value).map_err(|e| {
        error!("Error parsing ICAC");
        e
    });

    let invoke_resp = InvokeResponse::Command(CMD_PATH_NOCRESPONSE, |t| {
        // Status
        t.put_u8(TagType::Context(0), 0)?;
        // Fabric Index  - hard-coded for now
        t.put_u8(TagType::Context(1), 0)?;
        // Debug string
        t.put_str8(TagType::Context(2), b"")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)
}

fn command_csrrequest_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_CSRREQUEST_ID, handle_command_csrrequest)
}

fn command_addtrustedrootcert_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ADDTRUSTEDROOTCERT_ID, handle_command_addtrustedrootcert)
}

fn command_addnoc_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ADDNOC_ID, handle_command_addnoc)
}

pub fn cluster_operational_credentials_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_OPERATIONAL_CREDENTIALS_ID)?;
    cluster.add_command(command_csrrequest_new()?)?;
    cluster.add_command(command_addtrustedrootcert_new()?)?;
    cluster.add_command(command_addnoc_new()?)?;
    Ok(cluster)
}
