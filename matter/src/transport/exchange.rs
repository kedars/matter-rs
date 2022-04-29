use colored::*;
use log::{error, info, trace};
use std::any::Any;
use std::fmt;

use crate::error::Error;

use heapless::LinearMap;

use super::{
    mrp::ReliableMessage,
    packet::Packet,
    session::{SessionHandle, SessionMgr},
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ExchangeRole {
    Initiator = 0,
    Responder = 1,
}

impl Default for ExchangeRole {
    fn default() -> Self {
        ExchangeRole::Initiator
    }
}

#[derive(Debug, Default)]
pub struct Exchange {
    id: u16,
    sess_id: u16,
    role: ExchangeRole,
    // The number of users currently using this exchange. This will go away when
    // we start using Arc/Rc and the Exchange object itself is dynamically allocated
    // But, maybe that never happens
    user_cnt: u8,
    // Currently I see this primarily used in PASE and CASE. If that is the limited use
    // of this, we might move this into a separate data structure, so as not to burden
    // all 'exchanges'.
    data: Option<Box<dyn Any>>,
    mrp: ReliableMessage,
}

impl Exchange {
    pub fn new(id: u16, sess_id: u16, role: ExchangeRole) -> Exchange {
        Exchange {
            id,
            sess_id,
            role,
            user_cnt: 1,
            data: None,
            mrp: ReliableMessage::new(),
        }
    }

    pub fn close(&mut self) {
        self.data = None;
        self.release();
    }

    pub fn acquire(&mut self) {
        self.user_cnt += 1;
    }

    pub fn release(&mut self) {
        self.user_cnt -= 1;
        // Even if we get to a zero reference count, because the memory is static,
        // an exchange manager purge call is required to clean us up
    }

    pub fn is_purgeable(&self) -> bool {
        // No Users, No pending ACKs/Retrans
        self.user_cnt == 0 && self.mrp.is_empty()
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_role(&self) -> ExchangeRole {
        self.role
    }

    pub fn set_exchange_data(&mut self, data: Box<dyn Any>) {
        self.data = Some(data);
    }

    pub fn clear_exchange_data(&mut self) {
        self.data = None;
    }

    pub fn get_exchange_data<T: Any>(&mut self) -> Option<&mut T> {
        self.data.as_mut()?.downcast_mut::<T>()
    }

    pub fn take_exchange_data<T: Any>(&mut self) -> Option<Box<T>> {
        self.data.take()?.downcast::<T>().ok()
    }

    pub fn send(
        &mut self,
        proto_tx: &mut Packet,
        session: &mut SessionHandle,
    ) -> Result<(), Error> {
        trace!("payload: {:x?}", proto_tx.as_borrow_slice());
        info!(
            "{} with proto id: {} opcode: {}",
            "Sending".blue(),
            proto_tx.get_proto_id(),
            proto_tx.get_proto_opcode(),
        );

        if self.sess_id != session.get_local_sess_id() {
            error!("This should have never happened");
            return Err(Error::InvalidState);
        }
        proto_tx.proto.exch_id = self.id;
        if self.role == ExchangeRole::Initiator {
            proto_tx.proto.set_initiator();
        }

        session.pre_send(proto_tx)?;
        self.mrp.pre_send(proto_tx)?;
        session.send(proto_tx)
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exch_id: {:?}, sess_id: {}, role: {:?}, data: {:?}, use_cnt: {} mrp: {:?}",
            self.id, self.sess_id, self.role, self.data, self.user_cnt, self.mrp,
        )
    }
}

pub fn get_role(is_initiator: bool) -> ExchangeRole {
    if is_initiator {
        ExchangeRole::Initiator
    } else {
        ExchangeRole::Responder
    }
}

pub fn get_complementary_role(is_initiator: bool) -> ExchangeRole {
    if is_initiator {
        ExchangeRole::Responder
    } else {
        ExchangeRole::Initiator
    }
}

const MAX_EXCHANGES: usize = 8;

#[derive(Default)]
pub struct ExchangeMgr {
    // keys: exch-id
    exchanges: LinearMap<u16, Exchange, MAX_EXCHANGES>,
    sess_mgr: SessionMgr,
}

pub const MAX_MRP_ENTRIES: usize = 4;

impl ExchangeMgr {
    pub fn new(sess_mgr: SessionMgr) -> Self {
        Self {
            sess_mgr,
            exchanges: Default::default(),
        }
    }

    pub fn get_sess_mgr(&mut self) -> &mut SessionMgr {
        &mut self.sess_mgr
    }

    pub fn _get_with_id(
        exchanges: &mut LinearMap<u16, Exchange, MAX_EXCHANGES>,
        exch_id: u16,
    ) -> Option<&mut Exchange> {
        exchanges.get_mut(&exch_id)
    }

    pub fn get_with_id(&mut self, exch_id: u16) -> Option<&mut Exchange> {
        ExchangeMgr::_get_with_id(&mut self.exchanges, exch_id)
    }

    pub fn _get(
        exchanges: &mut LinearMap<u16, Exchange, MAX_EXCHANGES>,
        sess_id: u16,
        id: u16,
        role: ExchangeRole,
        create_new: bool,
    ) -> Result<&mut Exchange, Error> {
        // I don't prefer that we scan the list twice here (once for contains_key and other)
        if !exchanges.contains_key(&(id)) {
            if create_new {
                // If an exchange doesn't exist, create a new one
                info!("Creating new exchange");
                let e = Exchange::new(id, sess_id, role);
                if exchanges.insert(id, e).is_err() {
                    return Err(Error::NoSpace);
                }
            } else {
                return Err(Error::NoSpace);
            }
        }

        // At this point, we would either have inserted the record if 'create_new' was set
        // or it existed already
        if let Some(result) = exchanges.get_mut(&id) {
            if result.get_role() == role && sess_id == result.sess_id {
                Ok(result)
            } else {
                Err(Error::NoExchange)
            }
        } else {
            error!("This should never happen");
            Err(Error::NoSpace)
        }
    }
    pub fn get(
        &mut self,
        sess_id: u16,
        id: u16,
        role: ExchangeRole,
        create_new: bool,
    ) -> Result<&mut Exchange, Error> {
        ExchangeMgr::_get(&mut self.exchanges, sess_id, id, role, create_new)
    }

    pub fn recv(&mut self, proto_rx: &mut Packet) -> Result<(&mut Exchange, SessionHandle), Error> {
        // Get the session
        let mut session = self.sess_mgr.recv(proto_rx)?;

        // Decrypt the message
        session.recv(proto_rx)?;

        // Get the exchange
        let exch = ExchangeMgr::_get(
            &mut self.exchanges,
            proto_rx.plain.sess_id,
            proto_rx.proto.exch_id,
            get_complementary_role(proto_rx.proto.is_initiator()),
            // We create a new exchange, only if the peer is the initiator
            proto_rx.proto.is_initiator(),
        )?;

        // Message Reliability Protocol
        exch.mrp.recv(&proto_rx)?;

        Ok((exch, session))
    }

    pub fn send(&mut self, exch_id: u16, proto_tx: &mut Packet) -> Result<(), Error> {
        let exchange =
            ExchangeMgr::_get_with_id(&mut self.exchanges, exch_id).ok_or(Error::NoExchange)?;
        let mut session = self
            .sess_mgr
            .get_with_id(exchange.sess_id)
            .ok_or(Error::NoSession)?;
        exchange.send(proto_tx, &mut session)
    }

    pub fn purge(&mut self) {
        let mut to_purge: LinearMap<u16, (), MAX_EXCHANGES> = LinearMap::new();

        for (exch_id, exchange) in self.exchanges.iter() {
            if exchange.is_purgeable() {
                let _ = to_purge.insert(*exch_id, ());
            }
        }
        for (exch_id, _) in to_purge.iter() {
            self.exchanges.remove(&*exch_id);
        }
    }

    pub fn pending_acks(&mut self, expired_entries: &mut LinearMap<u16, (), MAX_MRP_ENTRIES>) {
        for (exch_id, exchange) in self.exchanges.iter() {
            if exchange.mrp.is_ack_ready() {
                expired_entries.insert(*exch_id, ()).unwrap();
            }
        }
    }
}

impl fmt::Display for ExchangeMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{  Session Mgr: {},", self.sess_mgr)?;
        writeln!(f, "  Exchanges: [")?;
        for s in &self.exchanges {
            writeln!(f, "{{ {}, }},", s.1)?;
        }
        writeln!(f, "  ]")?;
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use crate::transport::session::SessionMgr;

    use super::{ExchangeMgr, ExchangeRole};

    #[test]
    fn test_purge() {
        let sess_mgr = SessionMgr::new();
        let mut mgr = ExchangeMgr::new(sess_mgr);
        let _ = mgr.get(1, 2, ExchangeRole::Responder, true).unwrap();
        let _ = mgr.get(1, 3, ExchangeRole::Responder, true).unwrap();

        mgr.purge();
        assert_eq!(mgr.get_with_id(2).is_some(), true);
        assert_eq!(mgr.get_with_id(3).is_some(), true);

        // Release e1
        let e1 = mgr.get_with_id(2).unwrap();
        e1.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(2).is_some(), false);
        assert_eq!(mgr.get_with_id(3).is_some(), true);

        // Acquire e2
        let e2 = mgr.get_with_id(3).unwrap();
        e2.acquire();
        mgr.purge();
        assert_eq!(mgr.get_with_id(3).is_some(), true);

        // Release e2 once
        let e2 = mgr.get_with_id(3).unwrap();
        e2.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(3).is_some(), true);

        // Release e2 again
        let e2 = mgr.get_with_id(3).unwrap();
        e2.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(3).is_some(), false);
    }
}
