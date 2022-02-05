use crate::error::*;
use smol::net::{Ipv6Addr, UdpSocket};

// We could get rid of the smol here, but keeping it around in case we have to process
// any other events in this thread's context
pub struct UdpListener {
    socket: UdpSocket,
}

// Currently matches with the one in connectedhomeip repo
pub const MAX_RX_BUF_SIZE: usize = 1583;

/* The Matter Port */
const MATTER_PORT: u16 = 5540;

pub trait ConsumeMsg {
    fn consume_message(&mut self, msg: &mut [u8], len: usize, src: std::net::SocketAddr);
}

impl UdpListener {
    pub fn new() -> Result<UdpListener, Error> {
        Ok(UdpListener {
            socket: smol::block_on(UdpSocket::bind((Ipv6Addr::UNSPECIFIED, MATTER_PORT)))?,
        })
    }

    pub fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), Error> {
        let (size, addr) = smol::block_on(self.socket.recv_from(in_buf)).map_err(|e| {
            println!("Error on the network: {:?}", e);
            Error::Network
        })?;
        Ok((size, addr))
    }

    pub fn send(&self, out_buf: &[u8], addr: std::net::SocketAddr) -> Result<usize, Error> {
        Ok(smol::block_on(self.socket.send_to(out_buf, addr))?)
    }
}
