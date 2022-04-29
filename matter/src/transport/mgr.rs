use async_channel::Receiver;
use heapless::LinearMap;
use log::{debug, error, info, trace};

use crate::error::*;

use crate::transport::mrp::ReliableMessage;
use crate::transport::{
    exchange,
    packet::Packet,
    proto_demux::{self, ProtoRx},
    queue,
    session::{self, SessionHandle},
    udp::{self, MAX_RX_BUF_SIZE},
};
use colored::*;

use super::queue::Msg;

pub struct Mgr {
    transport: udp::UdpListener,
    exch_mgr: exchange::ExchangeMgr,
    proto_demux: proto_demux::ProtoDemux,
    rx_q: Receiver<Msg>,
}

impl Mgr {
    pub fn new() -> Result<Mgr, Error> {
        Ok(Mgr {
            transport: udp::UdpListener::new()?,
            proto_demux: proto_demux::ProtoDemux::new(),
            exch_mgr: exchange::ExchangeMgr::new(session::SessionMgr::new()),
            rx_q: queue::WorkQ::init()?,
        })
    }

    // Allows registration of different protocols with the Transport/Protocol Demux
    pub fn register_protocol(
        &mut self,
        proto_id_handle: Box<dyn proto_demux::HandleProto>,
    ) -> Result<(), Error> {
        self.proto_demux.register(proto_id_handle)
    }

    fn recv<'a>(
        transport: &mut udp::UdpListener,
        exch_mgr: &'a mut exchange::ExchangeMgr,
        in_buf: &'a mut [u8],
    ) -> Result<ProtoRx<'a>, Error> {
        let mut rx = Packet::new_rx()?;

        // Read from the transport
        let (len, src) = transport.recv(rx.as_borrow_slice())?;
        rx.get_parsebuf()?.set_len(len);
        rx.peer = src;

        info!("{} from src: {}", "Received".blue(), src);
        trace!("payload: {:x?}", rx.as_borrow_slice());

        // Get the exchange
        let (exchange, session) = exch_mgr.recv(&mut rx)?;
        debug!("Exchange is {:?}", exchange);

        // temporary hack
        let len = rx.as_borrow_slice().len();
        in_buf[..len].copy_from_slice(rx.as_borrow_slice());
        Ok(ProtoRx::new(
            rx.get_proto_id().into(),
            rx.get_proto_opcode(),
            session,
            exchange,
            src,
            &in_buf[..len],
        ))
    }

    fn send_to_exchange_id(
        &mut self,
        sess_id: u16,
        exch_id: u16,
        proto_tx: &mut Packet,
    ) -> Result<(), Error> {
        self.exch_mgr.send(exch_id, sess_id, proto_tx)?;
        let peer = proto_tx.peer;
        self.transport.send(proto_tx.as_borrow_slice(), peer)?;
        Ok(())
    }

    // This function is send_to_exchange(). There will be multiple higher layer send_*() functions
    // all of them will eventually call send_to_exchange() after creating the necessary session and exchange
    // objects
    fn send_to_exchange(
        transport: &udp::UdpListener,
        session: &mut SessionHandle,
        exchange: &mut exchange::Exchange,
        proto_tx: &mut Packet,
    ) -> Result<(), Error> {
        exchange.send(proto_tx, session)?;

        let peer = proto_tx.peer;
        transport.send(proto_tx.as_borrow_slice(), peer)?;
        Ok(())
    }

    fn handle_rxtx(&mut self, in_buf: &mut [u8], proto_tx: &mut Packet) -> Result<(), Error> {
        let mut rx_ctx =
            Mgr::recv(&mut self.transport, &mut self.exch_mgr, in_buf).map_err(|e| {
                error!("Error in recv: {:?}", e);
                e
            })?;

        // Proto Dispatch
        match self.proto_demux.handle(&mut rx_ctx, proto_tx) {
            Ok(r) => {
                if let proto_demux::ResponseRequired::No = r {
                    // We need to send the Ack if reliability is enabled, in this case
                    return Ok(());
                }
            }
            Err(e) => {
                error!("Error in proto_demux {:?}", e);
                return Err(e);
            }
        }

        // tx_ctx now contains the response payload, send the packet
        Mgr::send_to_exchange(
            &self.transport,
            &mut rx_ctx.session,
            rx_ctx.exchange,
            proto_tx,
        )
        .map_err(|e| {
            error!("Error in sending msg {:?}", e);
            e
        })?;

        Ok(())
    }

    fn handle_queue_msgs(&mut self) -> Result<(), Error> {
        if let Ok(msg) = self.rx_q.try_recv() {
            match msg {
                Msg::NewSession(new_session) => {
                    // If a new session was created, add it
                    let _ = self
                        .exch_mgr
                        .get_sess_mgr()
                        .add_session(new_session, |_| {})
                        .map_err(|e| error!("Error adding new session {:?}", e));
                }
                _ => {
                    error!("Queue Message Type not yet handled {:?}", msg);
                }
            }
        }
        Ok(())
    }

    pub fn start(&mut self) -> Result<(), Error> {
        loop {
            // I would have liked this in .bss instead of the stack, will likely move this
            // later when we convert this into a pool
            let mut in_buf: [u8; MAX_RX_BUF_SIZE] = [0; MAX_RX_BUF_SIZE];
            let mut proto_tx = match Packet::new_tx() {
                Ok(p) => p,
                Err(e) => {
                    error!("Error creating proto_tx {:?}", e);
                    continue;
                }
            };

            // Handle network operations
            self.handle_rxtx(&mut in_buf, &mut proto_tx)?;
            self.handle_queue_msgs()?;

            proto_tx.reset();

            // Handle any pending acknowledgement send
            let mut acks_to_send: LinearMap<(u16, u16), (), { exchange::MAX_MRP_ENTRIES }> =
                LinearMap::new();
            self.exch_mgr.pending_acks(&mut acks_to_send);
            for (sess_id, exch_id) in acks_to_send.keys() {
                info!(
                    "Sending MRP Standalone ACK for sess {} exch {}",
                    sess_id, exch_id
                );
                ReliableMessage::prepare_ack(*sess_id, *exch_id, &mut proto_tx);
                if let Err(e) = self.send_to_exchange_id(*sess_id, *exch_id, &mut proto_tx) {
                    error!("Error in sending Ack {:?}", e);
                }
            }

            // Handle exchange purging
            //    This need not be done in each turn of the loop, maybe once in 5 times or so?
            self.exch_mgr.purge();

            info!("Exchange Mgr: {}", self.exch_mgr);
        }
    }
}
