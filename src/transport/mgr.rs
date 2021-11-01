use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use log::{info, error};

use crate::error::*;
use crate::proto_demux;
use crate::transport::plain_hdr;
use crate::transport::enc_hdr;
use crate::transport::exchange;
use crate::transport::mrp;
use crate::transport::session;
use crate::transport::tx_ctx;
use crate::transport::udp;
use crate::utils::ParseBuf;

// Currently matches with the one in connectedhomeip repo
const MAX_RX_BUF_SIZE: usize = 1583;

#[derive(Default)]
pub struct RxCtx {
    src: Option<std::net::SocketAddr>,
    _len: usize,
    plain_hdr: plain_hdr::PlainHdr,
    enc_hdr: enc_hdr::EncHdr,
}

impl RxCtx {
    pub fn new(len: usize, src: std::net::SocketAddr) -> RxCtx {
        RxCtx{plain_hdr: plain_hdr::PlainHdr::default(),
              enc_hdr: enc_hdr::EncHdr::default(),
              _len: len,
              src: Some(src),
        }
    }
}

pub struct Mgr<'a> {
    transport: udp::UdpListener,
    sess_mgr:  session::SessionMgr,
    proto_demux: proto_demux::ProtoDemux<'a>,
}

impl<'a> Mgr<'a> {
    pub fn new() -> Result<Mgr<'a>, Error> {
        let mut mgr = Mgr{
            transport: udp::UdpListener::new()?,
            sess_mgr: session::SessionMgr::new(),
            proto_demux: proto_demux::ProtoDemux::new(),
        };

        // Create a fake entry as hard-coded in the 'bypass mode' in chip-tool
        let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let i2r_key = [ 0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8, 0x1b, 0x33];
        mgr.sess_mgr.add(0, 0, i2r_key, i2r_key, test_addr.ip()).unwrap();

        Ok(mgr)
    }

    // Allows registration of different protocols with the Transport/Protocol Demux
    pub fn register_protocol(&mut self, proto_id_handle: &'a mut dyn proto_demux::HandleProto) -> Result<(), Error> {
        return self.proto_demux.register(proto_id_handle);
    }

    pub fn start(&mut self) -> Result<(), Error>{
        /* I would have liked this in .bss instead of the stack, will likely move this later */
        let mut in_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];
        let mut out_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];

        loop {
            // Read from the transport
            let (len, src) = self.transport.recv(&mut in_buf)?;
            let mut rx_ctx = RxCtx::new(len, src);
            let mut parse_buf = ParseBuf::new(&mut in_buf, len);

            // Read unencrypted packet header
            match rx_ctx.plain_hdr.decode(&mut parse_buf) {
                Ok(_) => (),
                Err(_) => continue,
            };

            // Get session
            //      Ok to use unwrap here since we know 'src' is certainly not None
            let session = match self.sess_mgr.get(rx_ctx.plain_hdr.sess_id, rx_ctx.src.unwrap().ip()) {
                Some(a) => a,
                None => continue,
            };
            
            // Read encrypted header
            match rx_ctx.enc_hdr.decrypt_and_decode(&rx_ctx.plain_hdr, &mut parse_buf, &session.dec_key) {
                Ok(_) => (),
                Err(_) => continue,
            };

            // Get the exchange
            let exchange = match session.get_exchange(rx_ctx.enc_hdr.exch_id,
                                                    exchange::get_complementary_role(rx_ctx.enc_hdr.is_initiator()),
                                                    // We create a new exchange, only if the peer is the initiator
                                                    rx_ctx.enc_hdr.is_initiator()) {
                Some(e) => e,
                None => continue,
            };

            // Message Reliability Protocol
            mrp::on_msg_recv(exchange, &rx_ctx.plain_hdr, &rx_ctx.enc_hdr);

            info!("Exchange is {:?}", exchange);
            // Proto Dispatch
            let mut tx_ctx = match tx_ctx::TxCtx::new(&mut out_buf) {
                Ok(t) => t,
                Err(e) => { error!("Error while creating TxCtx: {:?}", e); continue; },
            };

            match self.proto_demux.handle(rx_ctx.enc_hdr.proto_id.into(), rx_ctx.enc_hdr.proto_opcode,
                                          parse_buf.as_slice(), &mut tx_ctx) {
                Ok(_) => (),
                Err(_) => continue,
            }

            // tx_ctx now contains the response payload, send it out
            match tx_ctx.send(session, rx_ctx.enc_hdr.exch_id, exchange::ExchangeRole::Responder) {
                Ok(_) => (),
                Err(_) => continue,
            }
        }
    }
}
