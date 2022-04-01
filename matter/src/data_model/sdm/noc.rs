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
use crate::tlv::{FromTLV, OctetStr, TLVElement, TLVWriter, TagType, ToTLV};
use crate::transport::session::SessionMode;
use crate::utils::writebuf::WriteBuf;
use crate::{cmd_enter, error::*};
use log::{error, info};
use num_derive::FromPrimitive;

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

pub const ID: u32 = 0x003E;

#[derive(FromPrimitive)]
pub enum Commands {
    AttReq = 0x00,
    AttReqResp = 0x01,
    CertChainReq = 0x02,
    CertChainResp = 0x03,
    CSRReq = 0x04,
    CSRResp = 0x05,
    AddNOC = 0x06,
    NOCResp = 0x08,
    AddTrustedRootCert = 0x0b,
}

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
            base: Cluster::new(ID)?,
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

        let r = AddNocReq::from_tlv(&cmd_req.data).map_err(|_| NocStatus::InvalidNOC)?;

        let noc_value = Cert::new(r.noc_value.0).map_err(|_| NocStatus::InvalidNOC)?;
        info!("Received NOC as: {}", noc_value);
        let icac_value = Cert::new(r.icac_value.0).map_err(|_| NocStatus::InvalidNOC)?;
        info!("Received ICAC as: {}", icac_value);

        let fabric = Fabric::new(
            noc_data.key_pair,
            noc_data.root_ca,
            icac_value,
            noc_value,
            None,
        )
        .map_err(|_| NocStatus::TableFull)?;
        let fab_idx = self
            .fabric_mgr
            .add(fabric)
            .map_err(|_| NocStatus::TableFull)?;

        if self.failsafe.record_add_noc(fab_idx).is_err() {
            error!("Failed to record NoC in the FailSafe, what to do?");
        }

        let cmd_data = |t: &mut TLVWriter| {
            // Status
            t.u8(TagType::Context(0), 0)?;
            // Fabric Index  - hard-coded for now
            t.u8(TagType::Context(1), fab_idx)?;
            // Debug string
            t.utf8(TagType::Context(2), b"")
        };
        let resp = ib::InvResp::cmd_new(0, ID, Commands::NOCResp as u16, &cmd_data);
        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_addnoc(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AddNOC");
        if let Err(e) = self._handle_command_addnoc(cmd_req) {
            let cmd_data = |t: &mut TLVWriter| {
                // Status
                t.u8(TagType::Context(0), e as u8)
            };
            let invoke_resp = ib::InvResp::cmd_new(0, ID, Commands::NOCResp as u16, &cmd_data);
            let _ = invoke_resp.to_tlv(cmd_req.resp, TagType::Anonymous);
            cmd_req.trans.complete();
        }
        Ok(())
    }

    fn handle_command_attrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("AttestationRequest");

        let req = CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received Attestation Nonce:{:?}", req.str);

        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let cmd_data = |t: &mut TLVWriter| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut attest_element = WriteBuf::new(&mut buf, RESP_MAX);

            add_attestation_element(&self.dev_att, req.str.0, &mut attest_element, t)?;
            add_attestation_signature(&self.dev_att, &mut attest_element, &attest_challenge, t)
        };
        let resp = ib::InvResp::cmd_new(0, ID, Commands::AttReqResp as u16, &cmd_data);
        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
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

        let cmd_data = |t: &mut TLVWriter| t.str16(TagType::Context(0), buf);
        let resp = ib::InvResp::cmd_new(0, ID, Commands::CertChainResp as u16, &cmd_data);
        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
        cmd_req.trans.complete();
        Ok(())
    }

    fn handle_command_csrrequest(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        cmd_enter!("CSRRequest");

        let req = CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
        info!("Received CSR Nonce:{:?}", req.str);

        if !self.failsafe.is_armed() {
            return Err(IMStatusCode::UnsupportedAccess);
        }

        let noc_keypair = KeyPair::new().map_err(|_| IMStatusCode::Failure)?;
        let mut attest_challenge = [0u8; crypto::SYMM_KEY_LEN_BYTES];
        attest_challenge.copy_from_slice(cmd_req.trans.session.get_att_challenge());

        let cmd_data = |t: &mut TLVWriter| {
            let mut buf: [u8; RESP_MAX] = [0; RESP_MAX];
            let mut nocsr_element = WriteBuf::new(&mut buf, RESP_MAX);

            add_nocsrelement(&noc_keypair, req.str.0, &mut nocsr_element, t)?;
            add_attestation_signature(&self.dev_att, &mut nocsr_element, &attest_challenge, t)
        };
        let resp = ib::InvResp::cmd_new(0, ID, Commands::CSRResp as u16, &cmd_data);

        let _ = resp.to_tlv(cmd_req.resp, TagType::Anonymous);
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

                let req =
                    CommonReq::from_tlv(&cmd_req.data).map_err(|_| IMStatusCode::InvalidCommand)?;
                info!("Received Trusted Cert:{:x?}", req.str);

                noc_data.root_ca = Cert::new(req.str.0).map_err(|_| IMStatusCode::Failure)?;
            }
            _ => (),
        }
        cmd_req.trans.complete();

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

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(|c| num::FromPrimitive::from_u32(c))
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;
        match cmd {
            Commands::AddNOC => self.handle_command_addnoc(cmd_req),
            Commands::CSRReq => self.handle_command_csrrequest(cmd_req),
            Commands::AddTrustedRootCert => self.handle_command_addtrustedrootcert(cmd_req),
            Commands::AttReq => self.handle_command_attrequest(cmd_req),
            Commands::CertChainReq => self.handle_command_certchainrequest(cmd_req),
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
    writer.start_struct(TagType::Anonymous)?;
    writer.str16(TagType::Context(1), cert_dec)?;
    writer.str8(TagType::Context(2), att_nonce)?;
    writer.u32(TagType::Context(3), epoch)?;
    writer.end_container()?;

    t.str16(TagType::Context(0), write_buf.as_borrow_slice())?;
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
    dac_key.sign_msg(attest_element.as_borrow_slice(), &mut signature)?;
    resp.str8(TagType::Context(1), &signature)
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
    writer.start_struct(TagType::Anonymous)?;
    writer.str8(TagType::Context(1), csr)?;
    writer.str8(TagType::Context(2), csr_nonce)?;
    writer.end_container()?;

    resp.str8(TagType::Context(0), write_buf.as_borrow_slice())?;
    Ok(())
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct AddNocReq<'a> {
    noc_value: OctetStr<'a>,
    icac_value: OctetStr<'a>,
    _ipk_value: OctetStr<'a>,
    _case_admin_node_id: u32,
    _vendor_id: u16,
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a")]
struct CommonReq<'a> {
    str: OctetStr<'a>,
}

#[derive(FromTLV)]
struct CertChainReq {
    cert_type: u8,
}

fn get_certchainrequest_params(data: &TLVElement) -> Result<DataType, Error> {
    let cert_type = CertChainReq::from_tlv(data)?.cert_type;

    const CERT_TYPE_DAC: u8 = 1;
    const CERT_TYPE_PAI: u8 = 2;
    info!("Received Cert Type:{:?}", cert_type);
    match cert_type {
        CERT_TYPE_DAC => Ok(dev_att::DataType::DAC),
        CERT_TYPE_PAI => Ok(dev_att::DataType::PAI),
        _ => Err(Error::Invalid),
    }
}
