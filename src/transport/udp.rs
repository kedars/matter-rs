use std::net::{Ipv4Addr, UdpSocket};
use crate::error::*;

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
        Ok(UdpListener{socket})
    }

    pub fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, std::net::SocketAddr), Error> {
        Ok(self.socket.recv_from(in_buf)?)
    }
}
