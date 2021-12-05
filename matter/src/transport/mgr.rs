use log::{debug, error, info, trace};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::error::*;
use crate::proto_demux;
use crate::proto_demux::ProtoRx;
use crate::proto_demux::ProtoTx;
use crate::transport::exchange;
use crate::transport::mrp;
use crate::transport::plain_hdr;
use crate::transport::proto_hdr;
use crate::transport::session;
use crate::transport::udp;
use crate::utils::parsebuf::ParseBuf;
use colored::*;

use super::session::Session;

// Currently matches with the one in connectedhomeip repo
const MAX_RX_BUF_SIZE: usize = 1583;

pub struct Mgr {
    transport: udp::UdpListener,
    sess_mgr: session::SessionMgr,
    exch_mgr: exchange::ExchangeMgr,
    proto_demux: proto_demux::ProtoDemux,
    rel_mgr: mrp::ReliableMessage,
}

impl Mgr {
    pub fn new() -> Result<Mgr, Error> {
        let mut mgr = Mgr {
            transport: udp::UdpListener::new()?,
            sess_mgr: session::SessionMgr::new(),
            proto_demux: proto_demux::ProtoDemux::new(),
            exch_mgr: exchange::ExchangeMgr::new(),
            rel_mgr: mrp::ReliableMessage::new(),
        };

        // Create a fake entry as hard-coded in the 'bypass mode' in chip-tool
        let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let i2r_key = [
            0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8,
            0x1b, 0x33,
        ];
        let r2i_key = [
            0xac, 0xc1, 0x8f, 0x06, 0xc7, 0xbc, 0x9b, 0xe8, 0x24, 0x6a, 0x67, 0x8c, 0xb1, 0xf8,
            0xba, 0x3d,
        ];

        let (_, session) = mgr.sess_mgr.add(test_addr.ip()).unwrap();
        session.activate(&i2r_key, &r2i_key, 0).unwrap();
        session.cheat_set_zero_local_sess_id();

        Ok(mgr)
    }

    // Allows registration of different protocols with the Transport/Protocol Demux
    pub fn register_protocol(
        &mut self,
        proto_id_handle: Box<dyn proto_demux::HandleProto>,
    ) -> Result<(), Error> {
        self.proto_demux.register(proto_id_handle)
    }

    // Borrow-checker gymnastics
    fn recv<'a>(
        transport: &mut udp::UdpListener,
        rel_mgr: &mut mrp::ReliableMessage,
        sess_mgr: &'a mut session::SessionMgr,
        exch_mgr: &'a mut exchange::ExchangeMgr,
        in_buf: &'a mut [u8],
    ) -> Result<ProtoRx<'a>, Error> {
        let mut plain_hdr = plain_hdr::PlainHdr::default();
        let mut proto_hdr = proto_hdr::ProtoHdr::default();

        // Read from the transport
        let (len, src) = transport.recv(in_buf)?;
        let mut parse_buf = ParseBuf::new(in_buf, len);

        info!("{} from src: {}", "Received".blue(), src);
        trace!("payload: {:x?}", parse_buf.as_borrow_slice());
        info!("Session Mgr: {}", sess_mgr);
        info!("Exchange Mgr: {}", exch_mgr);

        // Get session
        //      Ok to use unwrap here since we know 'src' is certainly not None
        let (_, session) = sess_mgr.recv(&mut plain_hdr, &mut parse_buf, src)?;

        // Read encrypted header
        session.recv(&plain_hdr, &mut proto_hdr, &mut parse_buf)?;

        // Get the exchange
        let exchange = exch_mgr.recv(&plain_hdr, &proto_hdr)?;
        debug!("Exchange is {:?}", exchange);

        // Message Reliability Protocol
        rel_mgr.recv(plain_hdr.sess_id, proto_hdr.exch_id, &plain_hdr, &proto_hdr)?;

        Ok(ProtoRx::new(
            proto_hdr.proto_id.into(),
            proto_hdr.proto_opcode,
            session,
            exchange,
            src,
            parse_buf.as_slice(),
        ))
    }

    // This function is send_to_exchange(). There will be a higher layer send() which will
    // internally call send_to_exchange() after creating the necessary session and exchange
    fn send_to_exchange(
        transport: &udp::UdpListener,
        rel_mgr: &mut mrp::ReliableMessage,
        proto_tx: &mut ProtoTx,
    ) -> Result<(), Error> {
        let mut plain_hdr = plain_hdr::PlainHdr::default();
        let mut proto_hdr = proto_hdr::ProtoHdr::default();

        trace!("payload: {:x?}", proto_tx.write_buf.as_slice());
        proto_hdr.proto_id = proto_tx.proto_id as u16;
        proto_hdr.proto_opcode = proto_tx.proto_opcode;

        let exchange = proto_tx.exchange.as_ref().ok_or(Error::NoExchange)?;
        exchange.send(&mut proto_hdr)?;

        let session = proto_tx.session.as_mut().ok_or(Error::NoSession)?;
        session.pre_send(&mut plain_hdr)?;

        rel_mgr.pre_send(
            session.get_local_sess_id(),
            exchange.get_id(),
            &plain_hdr,
            &mut proto_hdr,
        )?;

        session.send(&mut plain_hdr, &mut proto_hdr, &mut proto_tx.write_buf)?;

        transport.send(proto_tx.write_buf.as_slice(), proto_tx.peer)?;
        Ok(())
    }

    fn handle_rxtx(&mut self) -> Result<Option<Session>, Error> {
        // I would have liked this in .bss instead of the stack, will likely move this
        // later when we convert this into a pool
        let mut in_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];
        let mut out_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];

        let mut proto_rx = Mgr::recv(
            &mut self.transport,
            &mut self.rel_mgr,
            &mut self.sess_mgr,
            &mut self.exch_mgr,
            &mut in_buf,
        )
        .map_err(|e| {
            error!("Error in recv: {:?}", e);
            e
        })?;

        let mut proto_tx = ProtoTx::new(
            &mut out_buf,
            proto_rx.peer,
            plain_hdr::max_plain_hdr_len() + proto_hdr::max_proto_hdr_len(),
        )
        .map_err(|e| {
            error!("Error creating proto_tx {:?}", e);
            e
        })?;

        // Proto Dispatch
        match self.proto_demux.handle(&mut proto_rx, &mut proto_tx) {
            Ok(r) => {
                if let proto_demux::ResponseRequired::No = r {
                    // We need to send the Ack if reliability is enabled, in this case
                    return Ok(None);
                }
            }
            Err(e) => {
                error!("Error in proto_demux {:?}", e);
                return Err(e);
            }
        }
        // Check if a new session was created as part of the protocol handling
        let new_session = proto_tx.new_session.take();

        proto_tx.session = Some(proto_rx.session);
        proto_tx.exchange = Some(proto_rx.exchange);
        proto_tx.peer = proto_rx.peer;
        // tx_ctx now contains the response payload, prepare the send packet
        Mgr::send_to_exchange(&self.transport, &mut self.rel_mgr, &mut proto_tx).map_err(|e| {
            error!("Error in sending msg {:?}", e);
            e
        })?;
        Ok(new_session)
    }

    pub fn start(&mut self) -> Result<(), Error> {
        loop {
            if let Ok(new_session) = self.handle_rxtx() {
                // If a new session was created, add it
                if let Some(c) = new_session {
                    self.sess_mgr.add_session(c)?;
                }
            }
        }
    }
}
