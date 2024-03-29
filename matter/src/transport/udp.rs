use crate::error::*;
use smol::net::{Ipv6Addr, UdpSocket};

use super::network::{Address, NetworkInterface};

// We could get rid of the smol here, but keeping it around in case we have to process
// any other events in this thread's context
pub struct UdpListener {
    socket: UdpSocket,
}

// Currently matches with the one in connectedhomeip repo
pub const MAX_RX_BUF_SIZE: usize = 1583;

/* The Matter Port */
pub const MATTER_PORT: u16 = 5540;

impl UdpListener {
    pub fn new() -> Result<UdpListener, Error> {
        Ok(UdpListener {
            socket: smol::block_on(UdpSocket::bind((Ipv6Addr::UNSPECIFIED, MATTER_PORT)))?,
        })
    }
}

impl NetworkInterface for UdpListener {
    fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, Address), Error> {
        let (size, addr) = smol::block_on(self.socket.recv_from(in_buf)).map_err(|e| {
            println!("Error on the network: {:?}", e);
            Error::Network
        })?;
        Ok((size, Address::Udp(addr)))
    }

    fn send(&self, out_buf: &[u8], addr: Address) -> Result<usize, Error> {
        match addr {
            Address::Udp(addr) => Ok(smol::block_on(self.socket.send_to(out_buf, addr))?),
        }
    }
}
