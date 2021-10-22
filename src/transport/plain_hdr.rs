use crate::error::*;
use crate::utils::ParseBuf;
use log::info;
    
const SESSION_TYPE_MASK: u8 = 0x01;

#[derive(Debug)]
pub enum SessionType {
    None,
    Encrypted,
}

impl Default for SessionType {
    fn default() -> SessionType {
        SessionType::None
    }
}

// This is the unencrypted message
#[derive(Debug, Default)]
pub struct PlainHdr {
    pub flags: u8,
    /* For the current spec that this is working against, the security flags have following structure:
     * bit 0: if 1, AES-CCM crypto is used for the packet
     * other bits seem to be reserved
     */
    pub sess_type: SessionType,
    pub sess_id: u16,
    pub ctr: u32,
}

// it will have an additional 'message length' field first
pub fn parse_plain_hdr(msg: & mut ParseBuf) -> Result<PlainHdr, Error> {

    let flags = msg.le_u8()?;
    let sec_flags = msg.le_u8()?;
    let sess_id = msg.le_u16()?;
    let ctr = msg.le_u32()?;

    let sess_type = if (sec_flags & SESSION_TYPE_MASK) == 1 { SessionType::Encrypted } else { SessionType::None };

    info!("[plain_hdr] flags: {:x}, session type: {:#?}, sess_id: {}, ctr: {}", flags, sess_type, sess_id, ctr);

    Ok(PlainHdr{flags, sess_type, sess_id, ctr})
}

pub const fn max_plain_hdr_len() -> usize {
    return
    // [optional] msg len only for TCP
        2 +
    // flags
        1 +
    // security flags
        1 +
    // session ID
        2 +
    // message ctr
        4 +
    // [optional] source node ID
        8 +
    // [optional] destination node ID
        8;
}
