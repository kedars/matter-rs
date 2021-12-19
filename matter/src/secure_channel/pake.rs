use super::{
    common::{create_sc_status_report, SCStatusCodes},
    spake2p::Spake2P,
};
use crate::proto_demux::{ProtoRx, ProtoTx};
use crate::tlv::*;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::{error::Error, transport::session::CloneData};
use hkdf::Hkdf;
use log::error;
use rand::prelude::*;
use sha2::Sha256;

// This file basically deals with the handlers for the PASE secure channel protocol
// TLV extraction and encoding is done in this file.
// We create a Spake2p object and set it up in the exchange-data. This object then
// handles Spake2+ specific stuff.

// As per the spec the iteration count should be between 1000 and 100000
const ITERATION_COUNT: u32 = 2000;

// TODO: Password should be passed inside
const SPAKE2_PASSWORD: u32 = 123456;

const SPAKE2_SESSION_KEYS_INFO: [u8; 11] = *b"SessionKeys";

#[derive(Default)]
pub struct PAKE {
    // As per the spec the salt should be between 16 to 32 bytes
    salt: [u8; 16],
    passwd: u32,
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

    #[allow(non_snake_case)]
    pub fn handle_pasepake3(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut spake2_boxed = proto_rx
            .exchange
            .get_and_clear_exchange_data()
            .ok_or(Error::InvalidState)?;
        let spake2 = spake2_boxed
            .downcast_mut::<Spake2P>()
            .ok_or(Error::InvalidState)?;

        let cA = extract_pasepake_1_or_3_params(proto_rx.buf)?;
        let (status_code, Ke) = spake2.handle_cA(cA);

        if status_code == SCStatusCodes::SessionEstablishmentSuccess {
            // Get the keys
            let Ke = Ke.ok_or(Error::Invalid)?;
            let h = Hkdf::<Sha256>::new(None, Ke);
            let mut session_keys: [u8; 48] = [0; 48];
            h.expand(&SPAKE2_SESSION_KEYS_INFO, &mut session_keys)
                .map_err(|_x| Error::NoSpace)?;

            // Create a session
            let peer_sess_id = spake2.get_app_data() as u16;
            let mut clone_data = CloneData::new(peer_sess_id);
            clone_data.dec_key.copy_from_slice(&session_keys[0..16]);
            clone_data.enc_key.copy_from_slice(&session_keys[16..32]);
            clone_data
                .att_challenge
                .copy_from_slice(&session_keys[32..48]);
            proto_tx.new_session = Some(proto_rx.session.clone(&clone_data));
        }

        create_sc_status_report(proto_tx, status_code)?;
        proto_rx.exchange.close();
        Ok(())
    }

    #[allow(non_snake_case)]
    pub fn handle_pasepake1(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut spake2_boxed = proto_rx
            .exchange
            .get_and_clear_exchange_data()
            .ok_or(Error::InvalidState)?;
        let spake2 = spake2_boxed
            .downcast_mut::<Spake2P>()
            .ok_or(Error::InvalidState)?;

        let pA = extract_pasepake_1_or_3_params(proto_rx.buf)?;
        let mut pB: [u8; 65] = [0; 65];
        let mut cB: [u8; 32] = [0; 32];
        spake2.start_verifier(self.passwd, ITERATION_COUNT, &self.salt)?;
        spake2.handle_pA(pA, &mut pB, &mut cB)?;

        let mut tlvwriter = TLVWriter::new(&mut proto_tx.write_buf);
        tlvwriter.put_start_struct(TagType::Anonymous)?;
        tlvwriter.put_str8(TagType::Context(1), &pB)?;
        tlvwriter.put_str8(TagType::Context(2), &cB)?;
        tlvwriter.put_end_container()?;

        proto_rx.exchange.set_exchange_data(spake2_boxed);
        Ok(())
    }

    pub fn handle_pbkdfparamrequest(
        &mut self,
        proto_rx: &mut ProtoRx,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let (initiator_random, initiator_sessid, passcode_id, has_params) =
            extract_pbkdfreq_params(proto_rx.buf)?;
        if passcode_id != 0 {
            error!("Can't yet handle passcode_id != 0");
            return Err(Error::Invalid);
        }

        let mut our_random: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut our_random);

        let mut spake2p = Box::new(Spake2P::new());
        spake2p.set_app_data(initiator_sessid as u32);

        // Generate response
        let mut tlvwriter = TLVWriter::new(&mut proto_tx.write_buf);
        tlvwriter.put_start_struct(TagType::Anonymous)?;
        tlvwriter.put_str8(TagType::Context(1), initiator_random)?;
        tlvwriter.put_str8(TagType::Context(2), &our_random)?;
        tlvwriter.put_u16(
            TagType::Context(3),
            proto_rx.session.get_child_local_sess_id(),
        )?;
        if !has_params {
            tlvwriter.put_start_struct(TagType::Context(4))?;
            tlvwriter.put_u32(TagType::Context(1), ITERATION_COUNT)?;
            tlvwriter.put_str8(TagType::Context(2), &self.salt)?;
            tlvwriter.put_end_container()?;
        }
        tlvwriter.put_end_container()?;

        spake2p.set_context(proto_rx.buf, proto_tx.write_buf.as_slice());
        proto_rx.exchange.set_exchange_data(spake2p);
        Ok(())
    }
}

#[allow(non_snake_case)]
fn extract_pasepake_1_or_3_params(buf: &[u8]) -> Result<&[u8], Error> {
    let root = get_root_node_struct(buf)?;
    let pA = root.find_tag(1)?.get_slice()?;
    Ok(pA)
}

fn extract_pbkdfreq_params(buf: &[u8]) -> Result<(&[u8], u16, u16, bool), Error> {
    let root = get_root_node_struct(buf)?;
    let initiator_random = root.find_tag(1)?.get_slice()?;
    let initiator_sessid = root.find_tag(2)?.get_u8()?;
    let passcode_id = root.find_tag(3)?.get_u8()?;
    let has_params = root.find_tag(4)?.get_bool()?;
    Ok((
        initiator_random,
        initiator_sessid as u16,
        passcode_id as u16,
        has_params,
    ))
}

const PBKDF_RANDOM_LEN: usize = 32;
#[derive(Default)]
pub struct PBKDFParamReq {
    pub initiator_random: [u8; PBKDF_RANDOM_LEN],
    pub initiator_sessid: u16,
    pub passcode_id: u16,
    pub has_params: bool,
}

impl PBKDFParamReq {
    pub fn new(
        initiator_random_ref: &[u8],
        initiator_sessid: u16,
        passcode_id: u16,
        has_params: bool,
    ) -> Option<Self> {
        if initiator_random_ref.len() != PBKDF_RANDOM_LEN {
            None
        } else {
            let mut req = PBKDFParamReq::default();
            req.initiator_random.copy_from_slice(initiator_random_ref);
            req.initiator_sessid = initiator_sessid;
            req.passcode_id = passcode_id;
            req.has_params = has_params;
            Some(req)
        }
    }
}
