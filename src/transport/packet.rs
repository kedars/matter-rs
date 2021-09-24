use crate::transport::udp;
    
pub struct PacketParser {
    a: String,
}

impl PacketParser {
    pub fn new() -> PacketParser {
        PacketParser { a: String::from("Hi") }
    }
}

impl udp::ConsumeMsg for PacketParser {
    fn consume_message(&self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);


    }
}

