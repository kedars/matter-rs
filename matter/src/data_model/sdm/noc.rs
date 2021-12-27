use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cert::Cert;
// Node Operational Credentials Cluster
use crate::data_model::objects::*;
use crate::data_model::sdm::dev_att;
use crate::fabric::{Fabric, FabricMgr};
use crate::interaction_model::command::{self, CommandReq, InvokeRespIb};
use crate::interaction_model::CmdPathIb;
use crate::pki::pki::{self, KeyPair};
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::utils::writebuf::WriteBuf;
use crate::{cert, error::*};
use colored::Colorize;
use log::{error, info};

use super::dev_att::DevAttDataFetcher;

pub struct NOC {
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
}

impl NOC {
    pub fn new(dev_att: Box<dyn DevAttDataFetcher>, fabric_mgr: Arc<FabricMgr>) -> Self {
        Self {
            dev_att,
            fabric_mgr,
        }
    }
}

// Some placeholder value for now
const MAX_CERT_DECLARATION_LEN: usize = 300;
// Some placeholder value for now
const MAX_CSR_LEN: usize = 300;
// As defined in the Matter Spec
const RESP_MAX: usize = 900;

const CLUSTER_OPERATIONAL_CREDENTIALS_ID: u32 = 0x003E;

const CMD_ATTREQUEST_ID: u16 = 0x00;
const CMD_ATTRESPONSE_ID: u16 = 0x01;
const CMD_CERTCHAINREQUEST_ID: u16 = 0x02;
const CMD_CERTCHAINRESPONSE_ID: u16 = 0x03;
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

const CMD_PATH_CERTCHAINRESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_OPERATIONAL_CREDENTIALS_ID),
    command: CMD_CERTCHAINRESPONSE_ID,
};

const CMD_PATH_ATTRESPONSE: CmdPathIb = CmdPathIb {
    endpoint: Some(0),
    cluster: Some(CLUSTER_OPERATIONAL_CREDENTIALS_ID),
    command: CMD_ATTRESPONSE_ID,
};

#[derive(PartialEq)]
enum NocDataState {
    KeyPairGenerated,
    RootCAAdded,
}

struct NocData {
    pub key_pair: KeyPair,
    pub root_ca: Cert,
    pub state: NocDataState,
}

impl NocData {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            root_ca: Cert::default(),
            state: NocDataState::KeyPairGenerated,
        }
    }
}

fn add_attestation_element(
    dev_att: &Box<dyn DevAttDataFetcher>,
    att_nonce: &[u8],
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let mut cert_dec: [u8; MAX_CERT_DECLARATION_LEN] = [0; MAX_CERT_DECLARATION_LEN];
    let len = dev_att.get_devatt_data(dev_att::DataType::CertDeclaration, &mut cert_dec)?;
    let cert_dec = &cert_dec[0..len];

    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
    let mut write_buf = WriteBuf::new(&mut buf, RESP_MAX);
    let mut writer = TLVWriter::new(&mut write_buf);
    writer.put_start_struct(TagType::Anonymous)?;
    writer.put_str8(TagType::Context(1), cert_dec)?;
    writer.put_str8(TagType::Context(2), att_nonce)?;
    writer.put_u32(TagType::Context(3), epoch)?;
    writer.put_end_container()?;

    resp.put_str16(TagType::Context(0), write_buf.as_slice())?;
    Ok(())
}

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

fn get_addnoc_params<'a, 'b, 'c, 'd>(
    cmd_req: &mut CommandReq<'a, 'b, 'c, 'd>,
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

fn handle_command_attrequest(cluster: &mut Cluster, cmd_req: &mut CommandReq) -> Result<(), Error> {
    info!("{}", "Handling AttestationRequest".cyan());

    let att_nonce = cmd_req.data.find_tag(0)?.get_slice()?;
    info!("Received Attestation Nonce:{:?}", att_nonce);

    let noc = cluster.get_data::<NOC>().ok_or(Error::InvalidState)?;

    let invoke_resp = InvokeRespIb::Command(CMD_PATH_ATTRESPONSE, |t| {
        add_attestation_element(&noc.dev_att, att_nonce, t)?;
        t.put_str8(TagType::Context(1), b"ThisistheAttestationSignature")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn handle_command_certchainrequest(
    cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("{}", "Handling CertChainRequest".cyan());

    info!("Received data: {}", cmd_req.data);
    let cert_type = cmd_req
        .data
        .confirm_struct()?
        .iter()
        .ok_or(Error::InvalidData)?
        .next()
        .ok_or(Error::InvalidData)?
        .get_u8()?;

    const CERT_TYPE_DAC: u8 = 1;
    const CERT_TYPE_PAI: u8 = 2;
    info!("Received Cert Type:{:?}", cert_type);
    let cert_type = match cert_type {
        CERT_TYPE_DAC => dev_att::DataType::DAC,
        CERT_TYPE_PAI => dev_att::DataType::PAI,
        _ => {
            return Err(Error::InvalidData);
        }
    };

    let noc = cluster.get_data::<NOC>().ok_or(Error::InvalidState)?;

    let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
    let len = noc.dev_att.get_devatt_data(cert_type, &mut buf)?;
    let buf = &buf[0..len];

    let invoke_resp = InvokeRespIb::Command(CMD_PATH_CERTCHAINRESPONSE, |t| {
        t.put_str16(TagType::Context(0), buf)
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn handle_command_csrrequest(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    info!("{}", "Handling CSRRequest".cyan());

    let csr_nonce = cmd_req.data.find_tag(0)?.get_slice()?;
    info!("Received CSR Nonce:{:?}", csr_nonce);

    let noc_keypair = pki::KeyPair::new()?;

    let invoke_resp = InvokeRespIb::Command(CMD_PATH_CSRRESPONSE, |t| {
        add_nocsrelement(&noc_keypair, csr_nonce, t)?;
        t.put_str8(TagType::Context(1), b"ThisistheAttestationSignature")
    });

    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    let noc_data = Box::new(NocData::new(noc_keypair));
    // Store this in the session data instead of cluster data, so it gets cleared
    // if the session goes away for some reason
    cmd_req.trans.session.set_data(noc_data);
    cmd_req.trans.complete();
    Ok(())
}

fn handle_command_addtrustedrootcert(
    _cluster: &mut Cluster,
    cmd_req: &mut CommandReq,
) -> Result<(), Error> {
    let noc_data = cmd_req
        .trans
        .session
        .get_data::<NocData>()
        .ok_or(Error::InvalidState)?;

    if noc_data.state != NocDataState::KeyPairGenerated {
        // This handling will be incorrect once the RootCA is changed later on, but in that there will be an accessing Fabric
        // which doesn't exist at the time of PASE
        error!("Added RootCA without KeyPair generated");
        return Err(Error::InvalidState);
    }
    noc_data.state = NocDataState::RootCAAdded;
    info!("{}", "Handling AddTrustedRootCert".cyan());

    let root_cert = cmd_req.data.find_tag(0)?.get_slice()?;
    info!("Received Trusted Cert:{:?}", root_cert);

    noc_data.root_ca = Cert::new(root_cert);
    let invoke_resp = InvokeRespIb::Status(cmd_req.to_cmd_path_ib(), 0, 0, command::dummy);
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn handle_command_addnoc(cluster: &mut Cluster, cmd_req: &mut CommandReq) -> Result<(), Error> {
    let noc_data = cmd_req
        .trans
        .session
        .take_data::<NocData>()
        .ok_or(Error::InvalidState)?;
    if noc_data.state != NocDataState::RootCAAdded {
        // This handling will be incorrect once the RootCA is changed later on, but in that there will be an accessing Fabric
        // which doesn't exist at the time of PASE
        error!("AddNOC received with RootCA Added State");
        return Err(Error::InvalidState);
    }

    info!("{}", "Handling AddNOC".cyan());
    let (noc_value, icac_value, ipk_value, _case_admin_node_id, _vendor_id) =
        get_addnoc_params(cmd_req)?;

    info!("Received NOC as:");
    cert::print_cert(noc_value).map_err(|e| {
        error!("Error parsing NOC");
        e
    })?;

    info!("Received ICAC as:");
    let _ = cert::print_cert(icac_value).map_err(|e| {
        error!("Error parsing ICAC");
        e
    });

    let fabric = Fabric::new(
        noc_data.key_pair,
        noc_data.root_ca,
        Cert::new(icac_value),
        Cert::new(noc_value),
        Cert::new(ipk_value),
    )?;
    let fab_idx = cluster
        .get_data::<NOC>()
        .ok_or(Error::InvalidState)?
        .fabric_mgr
        .add(fabric)?;
    let invoke_resp = InvokeRespIb::Command(CMD_PATH_NOCRESPONSE, |t| {
        // Status
        t.put_u8(TagType::Context(0), 0)?;
        // Fabric Index  - hard-coded for now
        t.put_u8(TagType::Context(1), fab_idx)?;
        // Debug string
        t.put_utf8(TagType::Context(2), b"")
    });
    cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp)?;
    cmd_req.trans.complete();
    Ok(())
}

fn command_attrequest_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_ATTREQUEST_ID, handle_command_attrequest)
}

fn command_certchainrequest_new() -> Result<Box<Command>, Error> {
    Command::new(CMD_CERTCHAINREQUEST_ID, handle_command_certchainrequest)
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

pub fn cluster_operational_credentials_new(
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
) -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_OPERATIONAL_CREDENTIALS_ID)?;
    cluster.add_command(command_attrequest_new()?)?;
    cluster.add_command(command_certchainrequest_new()?)?;
    cluster.add_command(command_csrrequest_new()?)?;
    cluster.add_command(command_addtrustedrootcert_new()?)?;
    cluster.add_command(command_addnoc_new()?)?;

    let noc = Box::new(NOC::new(dev_att, fabric_mgr));
    cluster.set_data(noc);
    Ok(cluster)
}
