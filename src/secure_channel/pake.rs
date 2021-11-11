use super::spake2p::Spake2Mode;
use super::spake2p::Spake2P;
use crate::error::Error;
use crate::tlv::*;

use log::info;
pub struct PAKE {}
impl PAKE {
    pub fn new() -> Self {
        PAKE {}
    }

    pub fn handle_pbkdfparamrequest(&mut self, buf: &[u8]) -> Result<(), Error> {
        let (initiator_random, initiator_sessid, passcode_id, has_params) =
            extract_pbkdfreq_params(buf)?;
        info!(
            "random: {:x?} sessid: {} passid: {} hasparams:{}",
            initiator_random, initiator_sessid, passcode_id, has_params
        );
        let mut spake2p = Spake2P::new(Spake2Mode::Verifier);
        spake2p.add_to_context(buf);
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
