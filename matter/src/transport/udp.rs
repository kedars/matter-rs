use crate::error::*;
use futures_lite::future;
use smol::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

pub struct UdpListener {
    socketv4: UdpSocket,
    socketv6: UdpSocket,
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
        let socketv4 = future::block_on(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, MATTER_PORT)))?;
        let socketv6 = future::block_on(UdpSocket::bind((Ipv6Addr::UNSPECIFIED, MATTER_PORT)))?;
        Ok(UdpListener { socketv4, socketv6 })
    }

    pub fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), Error> {
        // TODO: I don't quite like that we need this extra buffer. I tried to use a small buffer
        // and a peek_from(), but for some reason, peek_from started returning EWOULDBLOCK, without
        // me having to set the socket to non-blocking.
        // Anyway, maintaining this at the lowermost level here, so hopefully the effect of this is nullified
        // because the rest of the stack space can be used by other deeper stack frames
        let mut extra_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];

        let (size, addr) = future::block_on(future::or(
            self.socketv4.recv_from(&mut extra_buf),
            self.socketv6.recv_from(in_buf),
        ))
        .map_err(|e| {
            println!("Error on the network: {:?}", e);
            Error::Network
        })?;
        if addr.is_ipv4() {
            // the data is in the extra buf in this case
            let len = extra_buf.len();
            in_buf[..len].copy_from_slice(&extra_buf[..]);
        }
        Ok((size, addr))
    }

    pub fn send(&self, out_buf: &[u8], addr: std::net::SocketAddr) -> Result<usize, Error> {
        let socket = if addr.is_ipv4() {
            &self.socketv4
        } else {
            &self.socketv6
        };

        Ok(future::block_on(socket.send_to(out_buf, addr))?)
    }
}
