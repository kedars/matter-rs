use super::common::*;
use crate::{error::Error, transport::tx_ctx::TxCtx};

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
    tx_ctx: &mut TxCtx,
    general_code: GeneralCode,
    proto_id: u32,
    proto_code: u16,
) -> Result<(), Error> {
    tx_ctx.set_proto_id(PROTO_ID_SECURE_CHANNEL as u16);
    tx_ctx.set_proto_opcode(OpCode::StatusReport as u8);
    let writebuf = tx_ctx.get_write_buf();
    writebuf.le_u16(general_code as u16)?;
    writebuf.le_u32(proto_id)?;
    writebuf.le_u16(proto_code)?;

    Ok(())
}
