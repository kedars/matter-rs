use heapless::Vec;
use log::info;
use crate::{
    error::*,
    transport::exchange::*
};

const MATTER_AES128_KEY_SIZE: usize = 16;

#[derive(Debug)]
pub struct Session {
    // If this field is None, the rest of the members are ignored
    peer_addr: Option<std::net::IpAddr>,
    pub dec_key: [u8; MATTER_AES128_KEY_SIZE],
    pub enc_key: [u8; MATTER_AES128_KEY_SIZE],
    /*
     *
     * - Session Role (whether we are session-Initiator or Session-Responder (use the correct key accordingly(
     * - local session ID (our ID assigned to this session)
     * - peer session ID (the peer's ID assigned to this session)
     * - local message counter (the one we'll use for our TX)
     * - message reception state (a list of counters already received from the peer) to detect duplicates
     * - peer Node ID - instead of the IP Address, which can change, the Node ID should be used
     * - This is all for 'unicast' sessions
     */
    sess_id: u16,
    peer_sess_id: u16,
    msg_ctr: u32,
    exchanges: Vec::<Exchange, 4>,
}

impl Session {
    pub fn get_exchange(&mut self, id: u16, role: ExchangeRole, create_new: bool) -> Option<&mut Exchange> {
        let index = self.exchanges.iter()
            .position(|x| x.is_match(id, role));
        if let Some(i) = index {
            Some(&mut self.exchanges[i])
        } else {
            // If an exchange doesn't exist, create a new one
            if create_new {
                info!("Creating new exchange");
                let e = Exchange::new(id, role);
                match self.exchanges.push(e) {
                    Ok(_) => {
                        // Return the exchange that was just added
                        return self.exchanges.iter_mut()
                            .find(|x| x.is_match(id, role));
                    },
                    Err(_) => return None,
                }
            } else {
                // Got a message that has no Exchange object
                return None;
            }
        }
    }

    pub fn new(sess_id: u16,
        peer_sess_id: u16,
        dec_key: [u8; MATTER_AES128_KEY_SIZE],
        enc_key: [u8; MATTER_AES128_KEY_SIZE],
        peer_addr: std::net::IpAddr) -> Session {
        Session {
            peer_addr  : Some(peer_addr),
            dec_key,
            enc_key,
            sess_id,
            peer_sess_id,
            msg_ctr: 1,
            exchanges: Vec::new(),
        }
    }

    pub fn get_sess_id(&self) -> u16 {
        self.sess_id
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
    }
    pub fn get_msg_ctr(&mut self) -> u32 {
        let ctr = self.msg_ctr;
        self.msg_ctr += 1;
        ctr
    }
}

#[derive(Debug)]
pub struct SessionMgr {
    pub sessions: Vec::<Session, 16>,
}

impl SessionMgr {
    pub fn new() -> SessionMgr {
        SessionMgr{
            sessions: Vec::new()
        }
    }
 
    pub fn add(&mut self, sess_id: u16,
               peer_sess_id: u16,
               dec_key: [u8; MATTER_AES128_KEY_SIZE],
               enc_key: [u8; MATTER_AES128_KEY_SIZE],
               peer_addr: std::net::IpAddr) -> Result<(), Error> {
        let session = Session::new(sess_id, peer_sess_id, dec_key, enc_key, peer_addr);
        match self.sessions.push(session) {
            Ok(_) => return Ok(()),
            Err(_) => return Err(Error::NoSpace),
        }
    }

    pub fn get(&mut self, sess_id: u16, peer_addr: std::net::IpAddr) -> Option<&mut Session> {
        if let Some(index) = self.sessions.iter().position(|x| {
            x.sess_id == sess_id &&
                x.peer_addr == Some(peer_addr)
        }) {
            return Some(&mut self.sessions[index]);
        }
        return None;
    }
}
