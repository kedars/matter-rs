use heapless::Vec;

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
     * - List of Exchanges: which in turn will have
     *    - message ack pending with the message counter to be ACKed
     *    - Exchange ID
     *    - Role: Initiator/Responder
     *    - 
     */
    session_id: u16,
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
 
    pub fn add(&mut self, session_id: u16,
               dec_key: [u8; MATTER_AES128_KEY_SIZE],
               enc_key: [u8; MATTER_AES128_KEY_SIZE],
               peer_addr: std::net::IpAddr) -> Result<(), &'static str> {
        let session = Session {
            peer_addr  : Some(peer_addr),
            dec_key,
            enc_key,
            session_id,
        };
        match self.sessions.push(session) {
            Ok(_) => return Ok(()),
            Err(_) => return Err("All sessions full"),
        }
    }

    pub fn get(&self, session_id: u16, peer_addr: std::net::IpAddr) -> Option<&Session> {
        if let Some(index) = self.sessions.iter().position(|x| {
            x.session_id == session_id &&
                x.peer_addr == Some(peer_addr)
        }) {
            return Some(&self.sessions[index]);
        }
        return None;
    }
}
