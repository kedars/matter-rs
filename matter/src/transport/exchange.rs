use log::{error, info};
use std::any::Any;
use std::fmt;

use crate::error::Error;

use heapless::LinearMap;

use super::{plain_hdr::PlainHdr, proto_hdr::ProtoHdr};

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
}

impl Exchange {
    pub fn new(id: u16, sess_id: u16, role: ExchangeRole) -> Exchange {
        Exchange {
            id,
            sess_id,
            role,
            user_cnt: 1,
            data: None,
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
        self.user_cnt == 0
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_role(&self) -> ExchangeRole {
        self.role
    }

    pub fn is_match(&self, id: u16, sess_id: u16, role: ExchangeRole) -> bool {
        self.id == id && self.sess_id == sess_id && self.role == role
    }

    pub fn is_match_ids(&self, id: u16, sess_id: u16) -> bool {
        self.id == id && self.sess_id == sess_id
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
        let t = self.data.take()?;
        t.downcast::<T>().ok()
    }

    pub fn send(&self, proto_hdr: &mut ProtoHdr) -> Result<(), Error> {
        proto_hdr.exch_id = self.id;
        if self.role == ExchangeRole::Initiator {
            proto_hdr.set_initiator();
        }
        Ok(())
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exch_id: {:?}, sess_id: {}, role: {:?}, data: {:?}, use_cnt: {}",
            self.id, self.sess_id, self.role, self.data, self.user_cnt
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
    // keys: sess-id exch-id
    exchanges: LinearMap<(u16, u16), Exchange, MAX_EXCHANGES>,
}

impl ExchangeMgr {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn get_with_id(&mut self, sess_id: u16, exch_id: u16) -> Option<&mut Exchange> {
        self.exchanges.get_mut(&(sess_id, exch_id))
    }

    pub fn get(
        &mut self,
        sess_id: u16,
        id: u16,
        role: ExchangeRole,
        create_new: bool,
    ) -> Result<&mut Exchange, Error> {
        // I don't prefer that we scan the list twice here (once for contains_key and other)
        if !self.exchanges.contains_key(&(sess_id, id)) {
            if create_new {
                // If an exchange doesn't exist, create a new one
                info!("Creating new exchange");
                let e = Exchange::new(id, sess_id, role);
                if self.exchanges.insert((sess_id, id), e).is_err() {
                    return Err(Error::NoSpace);
                }
            } else {
                return Err(Error::NoSpace);
            }
        }

        // At this point, we would either have inserted the record if 'create_new' was set
        // or it existed already
        if let Some(result) = self.exchanges.get_mut(&(sess_id, id)) {
            if result.get_role() == role {
                Ok(result)
            } else {
                Err(Error::NoExchange)
            }
        } else {
            error!("This should never happen");
            Err(Error::NoSpace)
        }
    }

    pub fn recv(
        &mut self,
        plain_hdr: &PlainHdr,
        proto_hdr: &ProtoHdr,
    ) -> Result<&mut Exchange, Error> {
        // Get the exchange
        self.get(
            plain_hdr.sess_id,
            proto_hdr.exch_id,
            get_complementary_role(proto_hdr.is_initiator()),
            // We create a new exchange, only if the peer is the initiator
            proto_hdr.is_initiator(),
        )
    }

    pub fn purge(&mut self) {
        let mut to_purge: LinearMap<(u16, u16), (), MAX_EXCHANGES> = LinearMap::new();

        for ((sess_id, exch_id), exchange) in self.exchanges.iter() {
            if exchange.is_purgeable() {
                let _ = to_purge.insert((*sess_id, *exch_id), ());
            }
        }
        for ((sess_id, exch_id), _) in to_purge.iter() {
            self.exchanges.remove(&(*sess_id, *exch_id));
        }
    }
}

impl fmt::Display for ExchangeMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{[")?;
        for s in &self.exchanges {
            writeln!(f, "{{ {}, }},", s.1)?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::{ExchangeMgr, ExchangeRole};

    #[test]
    fn test_purge() {
        let mut mgr = ExchangeMgr::new();
        let _ = mgr.get(1, 2, ExchangeRole::Responder, true).unwrap();
        let _ = mgr.get(1, 3, ExchangeRole::Responder, true).unwrap();

        mgr.purge();
        assert_eq!(mgr.get_with_id(1, 2).is_some(), true);
        assert_eq!(mgr.get_with_id(1, 3).is_some(), true);

        // Release e1
        let e1 = mgr.get_with_id(1, 2).unwrap();
        e1.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(1, 2).is_some(), false);
        assert_eq!(mgr.get_with_id(1, 3).is_some(), true);

        // Acquire e2
        let e2 = mgr.get_with_id(1, 3).unwrap();
        e2.acquire();
        mgr.purge();
        assert_eq!(mgr.get_with_id(1, 3).is_some(), true);

        // Release e2 once
        let e2 = mgr.get_with_id(1, 3).unwrap();
        e2.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(1, 3).is_some(), true);

        // Release e2 again
        let e2 = mgr.get_with_id(1, 3).unwrap();
        e2.release();
        mgr.purge();
        assert_eq!(mgr.get_with_id(1, 3).is_some(), false);
    }
}
