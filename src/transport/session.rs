use std::net::SocketAddr;
use heapless::Vec;

const MATTER_AES128_KEY_SIZE: usize = 16;

#[derive(Debug)]
pub struct Session {
    // If this field is None, the rest of the members are ignored
    peer_addr: Option<std::net::SocketAddr>,
    i2r_key: [u8; MATTER_AES128_KEY_SIZE],
    r2i_key: [u8; MATTER_AES128_KEY_SIZE],
    session_id: u16,
}

#[derive(Debug)]
pub struct SessionMgr {
    pub sessions: Vec::<Session, 16>,
}

pub static mut SESSIONS_MGR: SessionMgr = SessionMgr {
    sessions: Vec::new(),
};

impl SessionMgr {
    pub fn init() -> &'static mut SessionMgr {
        unsafe {
            &mut SESSIONS_MGR   
        }
    }
 
    pub fn add(&mut self, session_id: u16,
               i2r_key: [u8; MATTER_AES128_KEY_SIZE],
               r2i_key: [u8; MATTER_AES128_KEY_SIZE],
               peer_addr: std::net::SocketAddr) -> Result<(), &'static str> {
        let session = Session {
            peer_addr  : Some(peer_addr),
            i2r_key,
            r2i_key,
            session_id,
        };
        match self.sessions.push(session) {
            Ok(_) => return Ok(()),
            Err(_) => return Err("All sessions full"),
        }
    }

    pub fn get(&mut self, session_id: u16, peer_addr: std::net::SocketAddr) -> Option<&Session> {
        if let Some(index) = self.sessions.iter().position(|x| {
            x.session_id == session_id &&
                x.peer_addr == Some(peer_addr)
        }) {
            return Some(&self.sessions[index]);
        }
        return None;
    }
}
