use std::net::{Ipv4Addr, UdpSocket};

pub struct UdpListener<T: ConsumeMsg> {
    msg_consumer: T,
}

/* Currently matches with the one in connectedhomeip repo */
const MAX_BUF_SIZE: usize = 1583;

/* The Matter Port */
const MATTER_PORT: u16 = 5540;

pub trait ConsumeMsg {
    fn consume_message(&self, msg: &[u8], len: usize, src: std::net::SocketAddr);
}

impl<T: ConsumeMsg> UdpListener<T> {
    pub fn new(msg_consumer: T) -> UdpListener<T> {
        UdpListener {msg_consumer}
    }

    pub fn start_daemon(&self) -> Result<(), &'static str> {
        /* This is the buffer that holds incoming data. */
        /* I would have liked this to be a global variable, but Rust wants all access to such mutable static
         * variables to be 'unsafe', which I don't want to do.
         */
        let mut in_buf: [u8; MAX_BUF_SIZE] = [0; MAX_BUF_SIZE];

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, MATTER_PORT));
        let socket = match socket {
            Ok(s) => s,
            Err(_) => return Err("Error in creating socket"),
        };
        loop {
            let (len, src) = match socket.recv_from(&mut in_buf) {
                Ok((a, b)) => (a, b),
                Err(_) => return Err("Error in socket read"),
            };
            self.msg_consumer.consume_message(&mut in_buf, len, src);
        }
    }
}
