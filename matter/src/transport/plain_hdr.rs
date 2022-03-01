use crate::error::*;
use crate::utils::parsebuf::ParseBuf;
use crate::utils::writebuf::WriteBuf;
use log::info;

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
    pub sess_type: SessionType,
    pub sess_id: u16,
    pub ctr: u32,
    peer_nodeid: Option<u64>,
}

// A 64-bit nodeid is present
const DSIZ_UNICAST_NODEID: u8 = 0x01;
const _DSIZ_GROUPCAST_NODEID: u8 = 0x02;

impl PlainHdr {
    pub fn set_dest_u64(&mut self, id: u64) {
        self.flags |= DSIZ_UNICAST_NODEID;
        self.peer_nodeid = Some(id);
    }

    pub fn get_src_u64(&self) -> Option<u64> {
        if (self.flags & FLAG_SRC_ADDR_PRESENT) != 0 {
            self.peer_nodeid
        } else {
            None
        }
    }
}

const FLAG_SRC_ADDR_PRESENT: u8 = 0x04;
impl PlainHdr {
    // it will have an additional 'message length' field first
    pub fn decode(&mut self, msg: &mut ParseBuf) -> Result<(), Error> {
        self.flags = msg.le_u8()?;
        self.sess_id = msg.le_u16()?;
        let _sec_flags = msg.le_u8()?;
        self.sess_type = if self.sess_id != 0 {
            SessionType::Encrypted
        } else {
            SessionType::None
        };
        self.ctr = msg.le_u32()?;

        if (self.flags & FLAG_SRC_ADDR_PRESENT) != 0 {
            self.peer_nodeid = Some(msg.le_u64()?);
        }

        info!(
            "[decode] flags: {:x}, session type: {:#?}, sess_id: {}, ctr: {}",
            self.flags, self.sess_type, self.sess_id, self.ctr
        );
        Ok(())
    }

    pub fn encode(&mut self, resp_buf: &mut WriteBuf) -> Result<(), Error> {
        resp_buf.le_u8(self.flags)?;
        resp_buf.le_u16(self.sess_id)?;
        resp_buf.le_u8(0)?;
        resp_buf.le_u32(self.ctr)?;
        if let Some(d) = self.peer_nodeid {
            resp_buf.le_u64(d)?;
        }
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
