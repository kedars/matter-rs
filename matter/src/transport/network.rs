use std::{
    fmt::{Debug, Display},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use crate::error::Error;

#[derive(PartialEq, Copy, Clone)]
pub enum Address {
    Udp(SocketAddr),
}

impl Default for Address {
    fn default() -> Self {
        Address::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 8080))
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
        }
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Udp(addr) => writeln!(f, "{}", addr),
        }
    }
}

pub trait NetworkInterface {
    fn recv(&self, in_buf: &mut [u8]) -> Result<(usize, Address), Error>;
    fn send(&self, out_buf: &[u8], addr: Address) -> Result<usize, Error>;
}
