use num_derive::FromPrimitive;

use crate::{error::Error, proto_demux::ProtoTx};

use super::status_report::{create_status_report, GeneralCode};

/* Interaction Model ID as per the Matter Spec */
pub const PROTO_ID_SECURE_CHANNEL: usize = 0x00;

#[derive(FromPrimitive, Debug)]
pub enum OpCode {
    MsgCounterSyncReq = 0x00,
    MsgCounterSyncResp = 0x01,
    MRPStandAloneAck = 0x10,
    PBKDFParamRequest = 0x20,
    PBKDFParamResponse = 0x21,
    PASEPake1 = 0x22,
    PASEPake2 = 0x23,
    PASEPake3 = 0x24,
    CASESigma1 = 0x30,
    CASESigma2 = 0x31,
    CASESigma3 = 0x32,
    CASESigma2Resume = 0x33,
    StatusReport = 0x40,
}

#[derive(PartialEq)]
pub enum SCStatusCodes {
    SessionEstablishmentSuccess = 0,
    NoSharedTrustRoots = 1,
    InvalidParameter = 2,
    CloseSession = 3,
    Busy = 4,
    SessionNotFound = 5,
}

pub fn create_sc_status_report(
    proto_tx: &mut ProtoTx,
    status_code: SCStatusCodes,
) -> Result<(), Error> {
    let general_code = match status_code {
        SCStatusCodes::SessionEstablishmentSuccess | SCStatusCodes::CloseSession => {
            GeneralCode::Success
        }
        SCStatusCodes::Busy
        | SCStatusCodes::InvalidParameter
        | SCStatusCodes::NoSharedTrustRoots
        | SCStatusCodes::SessionNotFound => GeneralCode::Failure,
    };
    create_status_report(
        proto_tx,
        general_code,
        PROTO_ID_SECURE_CHANNEL as u32,
        status_code as u16,
    )
}
