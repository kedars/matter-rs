use super::spake2p::Spake2Mode;
use super::spake2p::Spake2P;
use crate::error::Error;
use crate::proto_demux::ProtoCtx;
use crate::tlv::*;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use crate::transport::tx_ctx::TxCtx;
use log::{error, info};
use rand::prelude::*;
pub struct PAKE {}
impl PAKE {
    pub fn new() -> Self {
        PAKE {}
    }

    pub fn handle_pbkdfparamrequest(
        &mut self,
        proto_ctx: &mut ProtoCtx,
        tx_ctx: &mut TxCtx,
    ) -> Result<(), Error> {
        let (initiator_random, initiator_sessid, passcode_id, has_params) =
            extract_pbkdfreq_params(proto_ctx.buf)?;
        info!(
            "random: {:x?} sessid: {} passid: {} hasparams:{}",
            initiator_random, initiator_sessid, passcode_id, has_params
        );

        proto_ctx.session.set_peer_sess_id(initiator_sessid);

        if passcode_id != 0 {
            error!("Can't yet handle passcode_id != 0");
            return Err(Error::Invalid);
        }

        if !has_params {
            error!("Can't yet handle has_params = false");
            return Err(Error::Invalid);
        }

        let mut our_random: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut our_random);

        let mut spake2p = Spake2P::new(Spake2Mode::Verifier);
        spake2p.add_to_context(proto_ctx.buf);

        // Generate response
        let mut tlvwriter = TLVWriter::new(tx_ctx.get_write_buf());
        tlvwriter.put_start_struct(TagType::Anonymous, 0)?;
        tlvwriter.put_str8(TagType::Context, 1, initiator_random)?;
        tlvwriter.put_str8(TagType::Context, 2, &our_random)?;
        tlvwriter.put_u16(TagType::Context, 3, proto_ctx.session.get_local_sess_id())?;
        tlvwriter.put_end_container()?;

        println!("Generated response: {:x?}", tx_ctx.as_slice());
        spake2p.add_to_context(tx_ctx.as_slice());
        Ok(())
    }
}

fn extract_pbkdfreq_params(buf: &[u8]) -> Result<(&[u8], u16, u16, bool), Error> {
    let root = get_root_node_struct(buf).ok_or(Error::InvalidData)?;
    let initiator_random = root
        .find_element(1)
        .ok_or(Error::Invalid)?
        .get_slice()
        .ok_or(Error::InvalidData)?;
    let initiator_sessid = root
        .find_element(2)
        .ok_or(Error::Invalid)?
        .get_u16()
        .ok_or(Error::Invalid)?;
    let passcode_id = root
        .find_element(3)
        .ok_or(Error::Invalid)?
        .get_u16()
        .ok_or(Error::Invalid)?;
    let has_params = root
        .find_element(4)
        .ok_or(Error::Invalid)?
        .get_bool()
        .ok_or(Error::Invalid)?;
    Ok((initiator_random, initiator_sessid, passcode_id, has_params))
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
