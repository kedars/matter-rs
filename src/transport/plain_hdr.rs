use crate::error::*;
use crate::utils::parsebuf::ParseBuf;
use crate::utils::writebuf::WriteBuf;
use log::info;

const SESSION_TYPE_MASK: u8 = 0x01;

#[derive(Debug, PartialEq)]
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

impl PlainHdr {
    // it will have an additional 'message length' field first
    pub fn decode(&mut self, msg: &mut ParseBuf) -> Result<(), Error> {
        self.flags = msg.le_u8()?;
        let sec_flags = msg.le_u8()?;
        self.sess_type = if (sec_flags & SESSION_TYPE_MASK) == 1 {
            SessionType::Encrypted
        } else {
            SessionType::None
        };
        self.sess_id = msg.le_u16()?;
        self.ctr = msg.le_u32()?;

        info!(
            "[decode] flags: {:x}, session type: {:#?}, sess_id: {}, ctr: {}",
            self.flags, self.sess_type, self.sess_id, self.ctr
        );
        Ok(())
    }

    pub fn encode(&mut self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        resp_buf.le_u8(self.flags)?;
        // XXX Not sure why this is 0x11, instead of 0x01
        resp_buf.le_u8(if self.sess_type == SessionType::Encrypted {
            0x11
        } else {
            0x10
        })?;
        resp_buf.le_u16(self.sess_id)?;
        resp_buf.le_u32(self.ctr)?;
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        self.sess_type == SessionType::Encrypted
    }
}

pub const fn max_plain_hdr_len() -> usize {
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
        8
}
