use std::any::Any;

use crate::{error::*, transport::exchange::*};
use heapless::Vec;
use log::info;

const MATTER_AES128_KEY_SIZE: usize = 16;

#[derive(Debug, PartialEq)]
pub enum SessionMode {
    Encrypted,
    PlainText,
}

impl Default for SessionMode {
    fn default() -> Self {
        SessionMode::PlainText
    }
}

#[derive(Debug)]
pub enum SessionState {
    Raw,
    Initialised,
}

impl Default for SessionState {
    fn default() -> Self {
        SessionState::Raw
    }
}

#[derive(Debug, Default)]
pub struct Session {
    // If this field is None, the rest of the members are ignored
    peer_addr: Option<std::net::IpAddr>,
    // I find the session initiator/responder role getting confused with exchange initiator/responder
    // So, we might keep this as enc_key and dec_key for now
    dec_key: [u8; MATTER_AES128_KEY_SIZE],
    enc_key: [u8; MATTER_AES128_KEY_SIZE],
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
    local_sess_id: u16,
    peer_sess_id: u16,
    // The local sess id is generated, but activated, only when the session creation is fully complete
    unassigned_local_sess_id: u16,
    msg_ctr: u32,
    exchanges: Vec<Exchange, 4>,
    mode: SessionMode,
    state: SessionState,
}

impl Session {
    pub fn new(reserved_local_sess_id: u16, peer_addr: std::net::IpAddr) -> Session {
        Session {
            peer_addr: Some(peer_addr),
            dec_key: [0; MATTER_AES128_KEY_SIZE],
            enc_key: [0; MATTER_AES128_KEY_SIZE],
            unassigned_local_sess_id: reserved_local_sess_id,
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: 1,
            exchanges: Vec::new(),
            mode: SessionMode::PlainText,
            state: SessionState::Raw,
        }
    }

    pub fn get_exchange(
        &mut self,
        id: u16,
        role: ExchangeRole,
        create_new: bool,
    ) -> Option<&mut Exchange> {
        let index = self.exchanges.iter().position(|x| x.is_match(id, role));
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
                        return self.exchanges.iter_mut().find(|x| x.is_match(id, role));
                    }
                    Err(_) => None,
                }
            } else {
                // Got a message that has no Exchange object
                None
            }
        }
    }

    pub fn set_exchange_data(
        &mut self,
        exch_id: u16,
        role: ExchangeRole,
        data: Box<dyn Any>,
    ) -> Result<(), Error> {
        self.get_exchange(exch_id, role, false)
            .ok_or(Error::NotFound)?
            .set_exchange_data(data);
        Ok(())
    }

    pub fn get_and_clear_exchange_data(
        &mut self,
        exch_id: u16,
        role: ExchangeRole,
    ) -> Option<Box<dyn Any>> {
        self.get_exchange(exch_id, role, false)
            .and_then(|e| e.get_and_clear_exchange_data())
    }

    pub fn clear_exchange_data(&mut self, exch_id: u16, role: ExchangeRole) -> Result<(), Error> {
        self.get_exchange(exch_id, role, false)
            .ok_or(Error::NotFound)?
            .clear_exchange_data();
        Ok(())
    }

    pub fn get_local_sess_id(&self) -> u16 {
        self.local_sess_id
    }

    pub fn get_reserved_local_sess_id(&self) -> u16 {
        self.unassigned_local_sess_id
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
    }

    pub fn set_local_sess_id(&mut self) {
        self.local_sess_id = self.unassigned_local_sess_id;
    }

    // This is required for the bypass case
    pub fn cheat_set_zero_local_sess_id(&mut self) {
        self.local_sess_id = 0;
    }

    pub fn is_encrypted(&self) -> bool {
        if self.mode == SessionMode::Encrypted {
            true
        } else {
            false
        }
    }

    pub fn get_msg_ctr(&mut self) -> u32 {
        let ctr = self.msg_ctr;
        self.msg_ctr += 1;
        ctr
    }

    pub fn get_dec_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Encrypted => Some(&self.dec_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn get_enc_key(&self) -> Option<&[u8]> {
        match self.mode {
            SessionMode::Encrypted => Some(&self.enc_key),
            SessionMode::PlainText => None,
        }
    }

    pub fn activate(
        &mut self,
        dec_key: &[u8],
        enc_key: &[u8],
        peer_sess_id: u16,
    ) -> Result<(), Error> {
        self.set_local_sess_id();
        self.peer_sess_id = peer_sess_id;
        if enc_key.len() == self.enc_key.len() {
            self.enc_key.copy_from_slice(enc_key);
        }
        if dec_key.len() == self.dec_key.len() {
            self.dec_key.copy_from_slice(dec_key);
        }
        self.mode = SessionMode::Encrypted;
        Ok(())
    }
}

#[derive(Debug)]
pub struct SessionMgr {
    next_sess_id: u16,
    pub sessions: Vec<Session, 16>,
}

impl SessionMgr {
    pub fn new() -> SessionMgr {
        SessionMgr {
            sessions: Vec::new(),
            next_sess_id: 1,
        }
    }

    fn get_next_sess_id(&mut self) -> u16 {
        let mut next_sess_id: u16;
        loop {
            next_sess_id = self.next_sess_id;

            // Increment next sess id
            self.next_sess_id = self.next_sess_id.overflowing_add(1).0;
            if self.next_sess_id == 0 {
                self.next_sess_id = 1;
            }

            // Ensure the currently selected id doesn't match any existing session
            if self.sessions.iter().position(|x| {
                x.local_sess_id == next_sess_id || x.unassigned_local_sess_id == next_sess_id
            }) == None
            {
                break;
            }
        }
        next_sess_id
    }

    pub fn add(&mut self, peer_addr: std::net::IpAddr) -> Result<&mut Session, Error> {
        let reserved_sess_id = self.get_next_sess_id();
        let session = Session::new(reserved_sess_id, peer_addr);

        match self.sessions.push(session) {
            Err(_) => return Err(Error::NoSpace),
            _ => (),
        };
        let index = self._get(0, peer_addr, false).ok_or(Error::NoSpace)?;
        Ok(&mut self.sessions[index])
    }

    fn _get(&self, sess_id: u16, peer_addr: std::net::IpAddr, is_encrypted: bool) -> Option<usize> {
        let mode = if is_encrypted {
            SessionMode::Encrypted
        } else {
            SessionMode::PlainText
        };
        self.sessions.iter().position(|x| {
            x.local_sess_id == sess_id && x.peer_addr == Some(peer_addr) && x.mode == mode
        })
    }

    pub fn get(
        &mut self,
        sess_id: u16,
        peer_addr: std::net::IpAddr,
        is_encrypted: bool,
    ) -> Option<&mut Session> {
        println!("Current sessions: {:?}", self.sessions);
        if let Some(index) = self._get(sess_id, peer_addr, is_encrypted) {
            println!("Found session");
            Some(&mut self.sessions[index])
        } else {
            println!("Not Found session");
            if sess_id == 0 && !is_encrypted {
                // We must create a new session for this case
                println!("Creating new session");
                self.add(peer_addr).ok()
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SessionMgr;
    use std::net::Ipv4Addr;

    #[test]
    fn test_next_sess_id_doesnt_reuse() {
        let mut sm = SessionMgr::new();
        sm.add(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap();
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        sm.add(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap();
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let mut sm = SessionMgr::new();
        sm.add(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .unwrap();
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }
}
