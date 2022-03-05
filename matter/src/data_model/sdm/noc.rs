use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cert::Cert;
use crate::crypto::{self, CryptoKeyPair, KeyPair};
use crate::data_model::objects::*;
use crate::data_model::sdm::dev_att;
use crate::fabric::{Fabric, FabricMgr};
use crate::interaction_model::command::CommandReq;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::ib;
use crate::tlv::TLVElement;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::transport::session::SessionMode;
use crate::utils::writebuf::WriteBuf;
use crate::{cmd_enter, command_path_ib, error::*};
use log::{error, info};

use super::dev_att::{DataType, DevAttDataFetcher};
use super::failsafe::FailSafe;

// Node Operational Credentials Cluster

#[derive(Clone, Copy)]
#[allow(dead_code)]
enum NocStatus {
    Ok = 0,
    InvalidPublicKey = 1,
    InvalidNodeOpId = 2,
    InvalidNOC = 3,
    MissingCsr = 4,
    TableFull = 5,
    MissingAcl = 6,
    MissingIpk = 7,
    InsufficientPrivlege = 8,
    FabricConflict = 9,
    LabelConflict = 10,
    InvalidFabricIndex = 11,
}

// Some placeholder value for now
const MAX_CERT_DECLARATION_LEN: usize = 600;
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

const CMD_PATH_CSRRESPONSE: ib::CmdPath =
    command_path_ib!(0, CLUSTER_OPERATIONAL_CREDENTIALS_ID, CMD_CSRRESPONSE_ID);

const CMD_PATH_NOCRESPONSE: ib::CmdPath =
    command_path_ib!(0, CLUSTER_OPERATIONAL_CREDENTIALS_ID, CMD_NOCRESPONSE_ID);

const CMD_PATH_CERTCHAINRESPONSE: ib::CmdPath = command_path_ib!(
    0,
    CLUSTER_OPERATIONAL_CREDENTIALS_ID,
    CMD_CERTCHAINRESPONSE_ID
);

const CMD_PATH_ATTRESPONSE: ib::CmdPath =
    command_path_ib!(0, CLUSTER_OPERATIONAL_CREDENTIALS_ID, CMD_ATTRESPONSE_ID);

pub struct NocCluster {
    base: Cluster,
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
    failsafe: Arc<FailSafe>,
}
struct NocData {
    pub key_pair: KeyPair,
    pub root_ca: Cert,
}

impl NocData {
    pub fn new(key_pair: KeyPair) -> Self {
        Self {
            key_pair,
            root_ca: Cert::default(),
        }
    }
}

impl NocCluster {
    pub fn new(
        dev_att: Box<dyn DevAttDataFetcher>,
        fabric_mgr: Arc<FabricMgr>,
        failsafe: Arc<FailSafe>,
    ) -> Result<Box<Self>, Error> {
        Ok(Box::new(Self {
            dev_att,
            fabric_mgr,
            failsafe,
            base: Cluster::new(CLUSTER_OPERATIONAL_CREDENTIALS_ID)?,
        }))
    }

    fn _handle_command_addnoc(&mut self, cmd_req: &mut CommandReq) -> Result<(), NocStatus> {
        let noc_data = cmd_req
            .trans
            .session
            .take_data::<NocData>()
            .ok_or(NocStatus::MissingCsr)?;

        if !self
            .failsafe
            .allow_noc_change()
            .map_err(|_| NocStatus::InsufficientPrivlege)?
        {
            error!("AddNOC not allowed by Fail Safe");
            return Err(NocStatus::InsufficientPrivlege);
        }

        let r = AddNocReq::new(&cmd_req.data).map_err(|_| NocStatus::InvalidNOC)?;

        let noc_value = Cert::new(r.noc_value);
        info!("Received NOC as: {}", noc_value);
        let icac_value = Cert::new(r.icac_value);
        info!("Received ICAC as: {}", icac_value);

        let fabric = Fabric::new(
            noc_data.key_pair,
            noc_data.root_ca,
            icac_value,
            noc_value,
            Cert::new(r.ipk_value),
        )
        .map_err(|_| NocStatus::TableFull)?;
        let fab_idx = self
            .fabric_mgr
            .add(fabric)
            .map_err(|_| NocStatus::TableFull)?;

        if self.failsafe.record_add_noc(fab_idx).is_err() {
            error!("Failed to record NoC in the FailSafe, what to do?");
        }
        let invoke_resp = ib::InvResponseOut::Cmd(CMD_PATH_NOCRESPONSE, |t| {
            // Status
            t.put_u8(TagType::Context(0), 0)?;
            // Fabric Index  - hard-coded for now
            t.put_u8(TagType::Context(1), fab_idx)?;
            // Debug string
            t.put_utf8(TagType::Context(2), b"")
        });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_addnoc(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AddNOC");
        if let Err(e) = self._handle_command_addnoc(cmd_req) {
            let invoke_resp = ib::InvResponseOut::Cmd(CMD_PATH_NOCRESPONSE, |t| {
                // Status
                t.put_u8(TagType::Context(0), e as u8)
            });
            let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
            cmd_req.trans.complete();
        }
        Ok(())
    }

    fn handle_command_attrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AttestationRequest");

        let att_nonce = cmd_req
            .data
            .find_tag(0)
            .map_err(|_| IMStatusCode::InvalidCommand)?
            .get_slice()
            .map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received Attestation Nonce:{:?}", att_nonce);

        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let invoke_resp = ib::InvResponseOut::Cmd(CMD_PATH_ATTRESPONSE, |t| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut attest_element = WriteBuf::new(&mut buf, RESP_MAX);

            add_attestation_element(&self.dev_att, att_nonce, &mut attest_element, t)?;
            add_attestation_signature(&self.dev_att, &mut attest_element, &attest_challenge, t)
        });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_certchainrequest(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("CertChainRequest");

        info!("Received data: {}", cmd_req.data);
        let cert_type =
            get_certchainrequest_params(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;

        let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
        let len = self
            .dev_att
            .get_devatt_data(cert_type, &mut buf)
            .map_err(|_| IMStatusCode::Failure)?;
        let buf = &buf[0..len];

        let invoke_resp = ib::InvResponseOut::Cmd(CMD_PATH_CERTCHAINRESPONSE, |t| {
            t.put_str16(TagType::Context(0), buf)
        });
        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_csrrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("CSRRequest");

        let csr_nonce = cmd_req
            .data
            .find_tag(0)
            .map_err(|_| IMStatusCode::InvalidCommand)?
            .get_slice()
            .map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received CSR Nonce:{:?}", csr_nonce);

        if !self.failsafe.is_armed() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        let noc_keypair = KeyPair::new().map_err(|_| IMStatusCode::Failure)?;
        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let invoke_resp = ib::InvResponseOut::Cmd(CMD_PATH_CSRRESPONSE, |t| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut nocsr_element = WriteBuf::new(&mut buf, RESP_MAX);

            add_nocsrelement(&noc_keypair, csr_nonce, &mut nocsr_element, t)?;
            add_attestation_signature(&self.dev_att, &mut nocsr_element, &attest_challenge, t)
        });

        let _ = cmd_req.resp.put_object(TagType::Anonymous, &invoke_resp);
        let noc_data = Box::new(NocData::new(noc_keypair));
        // Store this in the session data instead of cluster data, so it gets cleared
        // if the session goes away for some reason
        cmd_req.trans.session.set_data(noc_data);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_addtrustedrootcert(
        &mut self,
        cmd_req: &mut CommandReq,
    ) -> Result<(), IMStatusCode> {
        cmd_enter!("AddTrustedRootCert");
        if !self.failsafe.is_armed() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        // This may happen on CASE or PASE. For PASE, the existence of NOC Data is necessary
        match cmd_req.trans.session.get_session_mode() {
            SessionMode::Case(_) => error!("CASE: AddTrustedRootCert handling pending"), // For a CASE Session, we just return success for now,
            SessionMode::Pase => {
                let noc_data = cmd_req
                    .trans
                    .session
                    .get_data::<NocData>()
                    .ok_or(IMStatusCode::Failure)?;

                let root_cert = cmd_req
                    .data
                    .find_tag(0)
                    .map_err(|_| IMStatusCode::InvalidCommand)?
                    .get_slice()
                    .map_err(|_| IMStatusCode::InvalidCommand)?;
                info!("Received Trusted Cert:{:x?}", root_cert);

                noc_data.root_ca = Cert::new(root_cert);
            }
            _ => (),
        }
        Err(IMStatusCode::Sucess)
    }
}

impl ClusterType for NocCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error> {
        self.base.read_attribute(tag, tw, attr_id)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        match cmd {
            Some(CMD_ADDNOC_ID) => self.handle_command_addnoc(cmd_req),
            Some(CMD_CSRREQUEST_ID) => self.handle_command_csrrequest(cmd_req),
            Some(CMD_ADDTRUSTEDROOTCERT_ID) => self.handle_command_addtrustedrootcert(cmd_req),
            Some(CMD_ATTREQUEST_ID) => self.handle_command_attrequest(cmd_req),
            Some(CMD_CERTCHAINREQUEST_ID) => self.handle_command_certchainrequest(cmd_req),
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}

fn add_attestation_element(
    dev_att: &Box<dyn DevAttDataFetcher>,
    att_nonce: &[u8],
    write_buf: &mut WriteBuf,
    t: &mut TLVWriter,
) -> Result<(), Error> {
    let mut cert_dec: [u8; MAX_CERT_DECLARATION_LEN] = [0; MAX_CERT_DECLARATION_LEN];
    let len = dev_att.get_devatt_data(dev_att::DataType::CertDeclaration, &mut cert_dec)?;
    let cert_dec = &cert_dec[0..len];

    let epoch = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as u32;
    let mut writer = TLVWriter::new(write_buf);
    writer.put_start_struct(TagType::Anonymous)?;
    writer.put_str16(TagType::Context(1), cert_dec)?;
    writer.put_str8(TagType::Context(2), att_nonce)?;
    writer.put_u32(TagType::Context(3), epoch)?;
    writer.put_end_container()?;

    t.put_str16(TagType::Context(0), write_buf.as_slice())?;
    Ok(())
}

fn add_attestation_signature(
    dev_att: &Box<dyn DevAttDataFetcher>,
    attest_element: &mut WriteBuf,
    attest_challenge: &[u8],
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let dac_key = {
        let mut pubkey = [0_u8; crypto::EC_POINT_LEN_BYTES];
        let mut privkey = [0_u8; crypto::BIGNUM_LEN_BYTES];
        dev_att.get_devatt_data(dev_att::DataType::DACPubKey, &mut pubkey)?;
        dev_att.get_devatt_data(dev_att::DataType::DACPrivKey, &mut privkey)?;
        KeyPair::new_from_components(&pubkey, &privkey)
    }?;
    attest_element.copy_from_slice(attest_challenge)?;
    let mut signature = [0u8; crypto::EC_SIGNATURE_LEN_BYTES];
    dac_key.sign_msg(attest_element.as_slice(), &mut signature)?;
    resp.put_str8(TagType::Context(1), &signature)
}

fn add_nocsrelement(
    noc_keypair: &KeyPair,
    csr_nonce: &[u8],
    write_buf: &mut WriteBuf,
    resp: &mut TLVWriter,
) -> Result<(), Error> {
    let mut csr: [u8; MAX_CSR_LEN] = [0; MAX_CSR_LEN];
    let csr = noc_keypair.get_csr(&mut csr)?;
    let mut writer = TLVWriter::new(write_buf);
    writer.put_start_struct(TagType::Anonymous)?;
    writer.put_str8(TagType::Context(1), csr)?;
    writer.put_str8(TagType::Context(2), csr_nonce)?;
    writer.put_end_container()?;

    resp.put_str8(TagType::Context(0), write_buf.as_slice())?;
    Ok(())
}

struct AddNocReq<'a> {
    noc_value: &'a [u8],
    icac_value: &'a [u8],
    ipk_value: &'a [u8],
    _case_admin_node_id: u32,
    _vendor_id: u16,
}

impl<'a> AddNocReq<'a> {
    fn new(data: &'a TLVElement) -> Result<Self, Error> {
        let noc_value = data.find_tag(0)?.get_slice()?;
        let icac_value = data.find_tag(1)?.get_slice()?;
        let ipk_value = data.find_tag(2)?.get_slice()?;
        let case_admin_node_id = data.find_tag(3)?.get_u32()?;
        let vendor_id = data.find_tag(4)?.get_u16()?;
        Ok(Self {
            noc_value,
            icac_value,
            ipk_value,
            _case_admin_node_id: case_admin_node_id,
            _vendor_id: vendor_id,
        })
    }
}

fn get_certchainrequest_params(data: &TLVElement) -> Result<DataType, Error> {
    let cert_type = data
        .confirm_struct()?
        .iter()
        .ok_or(Error::Invalid)?
        .next()
        .ok_or(Error::Invalid)?
        .get_u8()?;

    const CERT_TYPE_DAC: u8 = 1;
    const CERT_TYPE_PAI: u8 = 2;
    info!("Received Cert Type:{:?}", cert_type);
    match cert_type {
        CERT_TYPE_DAC => Ok(dev_att::DataType::DAC),
        CERT_TYPE_PAI => Ok(dev_att::DataType::PAI),
        _ => Err(Error::Invalid),
    }
}
