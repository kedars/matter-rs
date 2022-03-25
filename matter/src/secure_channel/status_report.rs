use super::common::*;
use crate::{error::Error, proto_demux::ProtoTx};

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub enum GeneralCode {
    Success = 0,
    Failure = 1,
    BadPrecondition = 2,
    OutOfRange = 3,
    BadRequest = 4,
    Unsupported = 5,
    Unexpected = 6,
    ResourceExhausted = 7,
    Busy = 8,
    Timeout = 9,
    Continue = 10,
    Aborted = 11,
    InvalidArgument = 12,
    NotFound = 13,
    AlreadyExists = 14,
    PermissionDenied = 15,
    DataLoss = 16,
}
pub fn create_status_report(
    proto_tx: &mut ProtoTx,
    general_code: GeneralCode,
    proto_id: u32,
    proto_code: u16,
    proto_data: Option<&[u8]>,
) -> Result<(), Error> {
    proto_tx.proto_id = PROTO_ID_SECURE_CHANNEL;
    proto_tx.proto_opcode = OpCode::StatusReport as u8;
    proto_tx.write_buf.le_u16(general_code as u16)?;
    proto_tx.write_buf.le_u32(proto_id)?;
    proto_tx.write_buf.le_u16(proto_code)?;
    if let Some(s) = proto_data {
        proto_tx.write_buf.copy_from_slice(s)?;
    }

    Ok(())
}
