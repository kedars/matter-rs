use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};

use super::{
    common::{create_sc_status_report, SCStatusCodes},
    spake2p::Spake2P,
};
use crate::crypto;
use crate::tlv::{
    self, get_root_node_struct, FromTLV, OctetStr, TLVElement, TLVWriter, TagType, ToTLV,
};
use crate::{error::Error, transport::session::CloneData};
use crate::{
    proto_demux::{ProtoRx, ProtoTx},
    transport::session::SessionMode,
};
use log::{error, info};
use rand::prelude::*;

// This file basically deals with the handlers for the PASE secure channel protocol
// TLV extraction and encoding is done in this file.
// We create a Spake2p object and set it up in the exchange-data. This object then
// handles Spake2+ specific stuff.

// As per the spec the iteration count should be between 1000 and 100000
const ITERATION_COUNT: u32 = 2000;

// TODO: Password should be passed inside
const SPAKE2_PASSWORD: u32 = 123456;

const PASE_DISCARD_TIMEOUT_SECS: Duration = Duration::from_secs(60);

const SPAKE2_SESSION_KEYS_INFO: [u8; 11] = *b"SessionKeys";

struct SessionData {
    start_time: SystemTime,
    exch_id: u16,
    peer_addr: SocketAddr,
    spake2p: Box<Spake2P>,
}

impl SessionData {
    fn is_sess_expired(&self) -> Result<bool, Error> {
        if SystemTime::now().duration_since(self.start_time)? > PASE_DISCARD_TIMEOUT_SECS {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

enum PakeState {
    Idle,
    InProgress(SessionData),
}

impl PakeState {
    fn take(&mut self) -> Result<SessionData, Error> {
        let new = std::mem::replace(self, PakeState::Idle);
        if let PakeState::InProgress(s) = new {
            Ok(s)
        } else {
            Err(Error::InvalidSignature)
        }
    }

    fn is_idle(&self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(&PakeState::Idle)
    }

    fn take_sess_data(&mut self, proto_rx: &ProtoRx) -> Result<SessionData, Error> {
        let sd = self.take()?;
        if sd.exch_id != proto_rx.exchange.get_id()
            || sd.peer_addr != proto_rx.session.get_peer_addr()
        {
            Err(Error::InvalidState)
        } else {
            Ok(sd)
        }
    }

    fn make_in_progress(&mut self, spake2p: Box<Spake2P>, proto_rx: &ProtoRx) {
        *self = PakeState::InProgress(SessionData {
            start_time: SystemTime::now(),
            spake2p,
            exch_id: proto_rx.exchange.get_id(),
            peer_addr: proto_rx.session.get_peer_addr(),
        });
    }

    fn set_sess_data(&mut self, sd: SessionData) {
        *self = PakeState::InProgress(sd);
    }
}

impl Default for PakeState {
    fn default() -> Self {
        Self::Idle
    }
}

#[derive(Default)]
pub struct PAKE {
    // As per the spec the salt should be between 16 to 32 bytes
    salt: [u8; 16],
    passwd: u32,
    // Whether commissioning window/PASE session is enabled or not
    enabled: bool,
    state: PakeState,
}

impl PAKE {
    pub fn new() -> Self {
        // TODO: Can any PBKDF2 calculation be pre-computed here
        let mut pake = PAKE {
            passwd: SPAKE2_PASSWORD,
            ..Default::default()
        };
        rand::thread_rng().fill_bytes(&mut pake.salt);
        pake
    }

    pub fn enable(&mut self) {
        self.enabled = true;
    }

    pub fn disable(&mut self) {
        self.enabled = false;
    }

    #[allow(non_snake_case)]
    pub fn handle_pasepake3(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut sd = self.state.take_sess_data(proto_rx)?;

        let cA = extract_pasepake_1_or_3_params(proto_rx.buf)?;
        let (status_code, Ke) = sd.spake2p.handle_cA(cA);

        if status_code == SCStatusCodes::SessionEstablishmentSuccess {
            // Get the keys
            let Ke = Ke.ok_or(Error::Invalid)?;
            let mut session_keys: [u8; 48] = [0; 48];
            crypto::hkdf_sha256(&[], Ke, &SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
                .map_err(|_x| Error::NoSpace)?;

            // Create a session
            let data = sd.spake2p.get_app_data();
            let peer_sessid: u16 = (data & 0xff) as u16;
            let local_sessid: u16 = ((data >> 16) & 0xff) as u16;
            let mut clone_data = CloneData::new(peer_sessid, local_sessid, SessionMode::Pase);
            clone_data.dec_key.copy_from_slice(&session_keys[0..16]);
            clone_data.enc_key.copy_from_slice(&session_keys[16..32]);
            clone_data
                .att_challenge
                .copy_from_slice(&session_keys[32..48]);
            proto_tx.new_session = Some(proto_rx.session.clone(&clone_data));
        }

        create_sc_status_report(proto_tx, status_code, None)?;
        proto_rx.exchange.clear_exchange_data();
        proto_rx.exchange.close();
        // Disable PASE for subsequent sessions
        self.state = PakeState::Idle;
        self.disable();

        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn handle_pasepake1(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut sd = self.state.take_sess_data(proto_rx)?;

        let pA = extract_pasepake_1_or_3_params(proto_rx.buf)?;
        let mut pB: [u8; 65] = [0; 65];
        let mut cB: [u8; 32] = [0; 32];
        sd.spake2p
            .start_verifier(self.passwd, ITERATION_COUNT, &self.salt)?;
        sd.spake2p.handle_pA(pA, &mut pB, &mut cB)?;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let resp = Pake1Resp {
            pb: OctetStr(&pB),
            cb: OctetStr(&cB),
        };
        resp.to_tlv(&mut tw, TagType::Anonymous)?;

        self.state.set_sess_data(sd);

        Ok(())
    }

    pub fn handle_pbkdfparamrequest(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        if !self.enabled {
            error!("PASE Not enabled");
            create_sc_status_report(proto_tx, SCStatusCodes::InvalidParameter, None)?;
            return Ok(());
        }

        if !self.state.is_idle() {
            let sd = self.state.take()?;
            if sd.is_sess_expired()? {
                info!("Previous session expired, clearing it");
                self.state = PakeState::Idle;
            } else {
                info!("Previous session in-progress, denying new request");
                // little-endian timeout (here we've hardcoded 500ms)
                create_sc_status_report(proto_tx, SCStatusCodes::Busy, Some(&[0xf4, 0x01]))?;
                return Ok(());
            }
        }

        let root = tlv::get_root_node(proto_rx.buf)?;
        let a = PBKDFParamReq::from_tlv(&root)?;
        if a.passcode_id != 0 {
            error!("Can't yet handle passcode_id != 0");
            return Err(Error::Invalid);
        }

        let mut our_random: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut our_random);

        let local_sessid = proto_rx.session.reserve_new_sess_id();
        let spake2p_data: u32 = ((local_sessid as u32) << 16) | a.initiator_ssid as u32;
        let mut spake2p = Box::new(Spake2P::new());
        spake2p.set_app_data(spake2p_data as u32);

        // Generate response
        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let mut resp = PBKDFParamResp {
            init_random: a.initiator_random,
            our_random: OctetStr(&our_random),
            local_sessid,
            params: None,
        };
        if !a.has_params {
            let params_resp = PBKDFParamRespParams {
                count: ITERATION_COUNT,
                salt: OctetStr(&self.salt),
            };
            resp.params = Some(params_resp);
        }
        resp.to_tlv(&mut tw, TagType::Anonymous)?;

        spake2p.set_context(proto_rx.buf, proto_tx.write_buf.as_borrow_slice())?;
        self.state.make_in_progress(spake2p, proto_rx);
        Ok(())
    }
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
struct Pake1Resp<'a> {
    pb: OctetStr<'a>,
    cb: OctetStr<'a>,
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
struct PBKDFParamRespParams<'a> {
    count: u32,
    salt: OctetStr<'a>,
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
struct PBKDFParamResp<'a> {
    init_random: OctetStr<'a>,
    our_random: OctetStr<'a>,
    local_sessid: u16,
    params: Option<PBKDFParamRespParams<'a>>,
}

#[allow(non_snake_case)]
fn extract_pasepake_1_or_3_params(buf: &[u8]) -> Result<&[u8], Error> {
    let root = get_root_node_struct(buf)?;
    let pA = root.find_tag(1)?.slice()?;
    Ok(pA)
}

#[derive(FromTLV)]
#[tlvargs(lifetime = "'a", start = 1)]
struct PBKDFParamReq<'a> {
    initiator_random: OctetStr<'a>,
    initiator_ssid: u8,
    passcode_id: u8,
    has_params: bool,
}
