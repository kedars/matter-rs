use async_channel::Receiver;
use boxslab::{BoxSlab, Slab};
use heapless::LinearMap;
use log::{debug, error, info, trace};

use crate::error::*;

use crate::transport::mrp::ReliableMessage;
use crate::transport::packet::PacketPool;
use crate::transport::{
    exchange::{self, ExchangeCtx},
    packet::Packet,
    proto_demux::{self},
    queue,
    session::{self},
    udp::{self},
};
use colored::*;

use super::proto_demux::ProtoCtx;
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
    ) -> Result<(ExchangeCtx<'a>, BoxSlab<PacketPool>), Error> {
        let mut rx = Slab::<PacketPool>::new(Packet::new_rx()?).ok_or(Error::PacketPoolExhaust)?;

        // Read from the transport
        let (len, src) = transport.recv(rx.as_borrow_slice())?;
        rx.get_parsebuf()?.set_len(len);
        rx.peer = src;

        info!("{} from src: {}", "Received".blue(), src);
        trace!("payload: {:x?}", rx.as_borrow_slice());

        // Get the exchange
        let exch_ctx = exch_mgr.recv(&mut rx)?;
        debug!("Exchange is {:?}", exch_ctx.exch);

        Ok((exch_ctx, rx))
    }

    fn send_to_exchange_id(&mut self, exch_id: u16, proto_tx: &mut Packet) -> Result<(), Error> {
        self.exch_mgr.send(exch_id, proto_tx)?;
        let peer = proto_tx.peer;
        self.transport.send(proto_tx.as_borrow_slice(), peer)?;
        Ok(())
    }

    // This function is send_to_exchange(). There will be multiple higher layer send_*() functions
    // all of them will eventually call send_to_exchange() after creating the necessary session and exchange
    // objects
    fn send_to_exchange(
        transport: &udp::UdpListener,
        exch_ctx: &mut exchange::ExchangeCtx,
        mut proto_tx: BoxSlab<PacketPool>,
    ) -> Result<(), Error> {
        exch_ctx.send(&mut proto_tx)?;

        let peer = proto_tx.peer;
        transport.send(proto_tx.as_borrow_slice(), peer)?;
        Ok(())
    }

    fn handle_rxtx(&mut self) -> Result<(), Error> {
        let (exch_ctx, rx) = Mgr::recv(&mut self.transport, &mut self.exch_mgr).map_err(|e| {
            error!("Error in recv: {:?}", e);
            e
        })?;
        let tx = Self::new_tx()?;

        let mut proto_ctx = ProtoCtx::new(exch_ctx, rx, tx);
        // Proto Dispatch
        match self.proto_demux.handle(&mut proto_ctx) {
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

        let ProtoCtx {
            mut exch_ctx,
            rx: _,
            tx,
        } = proto_ctx;
        // tx_ctx now contains the response payload, send the packet
        Mgr::send_to_exchange(&self.transport, &mut exch_ctx, tx).map_err(|e| {
            error!("Error in sending msg {:?}", e);
            e
        })?;

        Ok(())
    }

    fn handle_queue_msgs(&mut self) -> Result<(), Error> {
        if let Ok(msg) = self.rx_q.try_recv() {
            match msg {
                Msg::NewSession(clone_data) => {
                    // If a new session was created, add it
                    let _ = self
                        .exch_mgr
                        .add_session(clone_data)
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
            // Handle network operations
            if self.handle_rxtx().is_err() {
                error!("Error in handle_rxtx");
                continue;
            }

            if self.handle_queue_msgs().is_err() {
                error!("Error in handle_queue_msg");
                continue;
            }

            let mut proto_tx = match Self::new_tx() {
                Ok(p) => p,
                Err(e) => {
                    error!("Error creating proto_tx {:?}", e);
                    continue;
                }
            };

            // Handle any pending acknowledgement send
            let mut acks_to_send: LinearMap<u16, (), { exchange::MAX_MRP_ENTRIES }> =
                LinearMap::new();
            self.exch_mgr.pending_acks(&mut acks_to_send);
            for exch_id in acks_to_send.keys() {
                info!("Sending MRP Standalone ACK for  exch {}", exch_id);
                ReliableMessage::prepare_ack(*exch_id, &mut proto_tx);
                if let Err(e) = self.send_to_exchange_id(*exch_id, &mut proto_tx) {
                    error!("Error in sending Ack {:?}", e);
                }
            }

            // Handle exchange purging
            //    This need not be done in each turn of the loop, maybe once in 5 times or so?
            self.exch_mgr.purge();

            info!("Exchange Mgr: {}", self.exch_mgr);
        }
    }

    fn new_tx() -> Result<BoxSlab<PacketPool>, Error> {
        Slab::<PacketPool>::new(Packet::new_tx()?).ok_or(Error::PacketPoolExhaust)
    }
}
