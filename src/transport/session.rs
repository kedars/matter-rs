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

    pub fn new(
        reserved_local_sess_id: u16,
        dec_key: [u8; MATTER_AES128_KEY_SIZE],
        enc_key: [u8; MATTER_AES128_KEY_SIZE],
        peer_addr: std::net::IpAddr,
        mode: SessionMode,
    ) -> Session {
        Session {
            peer_addr: Some(peer_addr),
            dec_key,
            enc_key,
            unassigned_local_sess_id: reserved_local_sess_id,
            peer_sess_id: 0,
            local_sess_id: 0,
            msg_ctr: 1,
            exchanges: Vec::new(),
            mode,
            state: SessionState::Raw,
        }
    }

    pub fn get_local_sess_id(&self) -> u16 {
        self.local_sess_id
    }

    pub fn get_peer_sess_id(&self) -> u16 {
        self.peer_sess_id
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

    // This is a cheat add that is present only to support bypass mode, it creates a session with local sess id as 0
    pub fn add_cheat(
        &mut self,
        dec_key: [u8; MATTER_AES128_KEY_SIZE],
        enc_key: [u8; MATTER_AES128_KEY_SIZE],
        peer_addr: std::net::IpAddr,
        mode: SessionMode,
    ) -> Result<(), Error> {
        let session = Session::new(0, dec_key, enc_key, peer_addr, mode);
        match self.sessions.push(session) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::NoSpace),
        }
    }

    pub fn add(
        &mut self,
        dec_key: [u8; MATTER_AES128_KEY_SIZE],
        enc_key: [u8; MATTER_AES128_KEY_SIZE],
        peer_addr: std::net::IpAddr,
        mode: SessionMode,
    ) -> Result<&mut Session, Error> {
        let reserved_sess_id = self.get_next_sess_id();
        let session = Session::new(reserved_sess_id, dec_key, enc_key, peer_addr, mode);

        match self.sessions.push(session) {
            Err(_) => return Err(Error::NoSpace),
            _ => (),
        };
        let index = self._get(0, peer_addr).ok_or(Error::NoSpace)?;
        Ok(&mut self.sessions[index])
    }

    fn _get(&self, sess_id: u16, peer_addr: std::net::IpAddr) -> Option<usize> {
        self.sessions
            .iter()
            .position(|x| x.local_sess_id == sess_id && x.peer_addr == Some(peer_addr))
    }

    pub fn get(
        &mut self,
        sess_id: u16,
        peer_addr: std::net::IpAddr,
        is_encrypted: bool,
    ) -> Option<&mut Session> {
        if let Some(index) = self._get(sess_id, peer_addr) {
            Some(&mut self.sessions[index])
        } else {
            if sess_id == 0 && !is_encrypted {
                // We must create a new session for this case
                self.add(
                    [0; MATTER_AES128_KEY_SIZE],
                    [0; MATTER_AES128_KEY_SIZE],
                    peer_addr,
                    SessionMode::PlainText,
                )
                .ok()
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
        let dec_key: [u8; 16] = [0; 16];
        let mut sm = SessionMgr::new();
        sm.add(
            dec_key,
            dec_key,
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            super::SessionMode::PlainText,
        )
        .unwrap();
        assert_eq!(sm.get_next_sess_id(), 2);
        assert_eq!(sm.get_next_sess_id(), 3);
        sm.add(
            dec_key,
            dec_key,
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            super::SessionMode::PlainText,
        )
        .unwrap();
        assert_eq!(sm.get_next_sess_id(), 5);
    }

    #[test]
    fn test_next_sess_id_overflows() {
        let dec_key: [u8; 16] = [0; 16];
        let mut sm = SessionMgr::new();
        sm.add(
            dec_key,
            dec_key,
            std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            super::SessionMode::PlainText,
        )
        .unwrap();
        assert_eq!(sm.get_next_sess_id(), 2);
        sm.next_sess_id = 65534;
        assert_eq!(sm.get_next_sess_id(), 65534);
        assert_eq!(sm.get_next_sess_id(), 65535);
        assert_eq!(sm.get_next_sess_id(), 2);
    }
}
