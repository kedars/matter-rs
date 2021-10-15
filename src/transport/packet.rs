use crate::error::*;
use crate::utils::ParseBuf;
    
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
    let mut flags    : u8 = 0;
    let mut sec_flags: u8 = 0;
    let mut sess_id  : u16 = 0;
    let mut ctr      : u32 = 0;

    msg.le_u8(&mut flags)?;
    msg.le_u8(&mut sec_flags)?;
    msg.le_u16(&mut sess_id)?;
    msg.le_u32(&mut ctr)?;

    let sess_type = if (sec_flags & SESSION_TYPE_MASK) == 1 { SessionType::Encrypted } else { SessionType::None };

    println!("flags: {:x}", flags);
    println!("session type: {:#?}", sess_type);
    println!("sess_id: {}", sess_id);
    println!("ctr: {}", ctr);

    Ok(PlainHdr{flags, sess_type, sess_id, ctr})
}

