use crate::error::*;
use std::net::{Ipv4Addr, UdpSocket};

pub struct UdpListener {
    socket: UdpSocket,
}

/* The Matter Port */
const MATTER_PORT: u16 = 5540;

pub trait ConsumeMsg {
    fn consume_message(&mut self, msg: &mut [u8], len: usize, src: std::net::SocketAddr);
}

impl UdpListener {
    pub fn new() -> Result<UdpListener, Error> {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, MATTER_PORT))?;
        Ok(UdpListener { socket })
    }

    pub fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), Error> {
        Ok(self.socket.recv_from(in_buf)?)
    }

    pub fn send(&self, out_buf: &[u8], addr: std::net::SocketAddr) -> Result<usize, Error> {
        Ok(self.socket.send_to(out_buf, addr)?)
    }
}
