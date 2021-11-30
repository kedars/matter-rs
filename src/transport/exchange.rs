use log::info;
use std::any::Any;
use std::fmt;

use crate::error::Error;

#[derive(Debug, PartialEq, Copy, Clone)]
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
            data: None,
        }
    }

    pub fn get_id(&self) -> u16 {
        self.id
    }

    pub fn get_role(&self) -> ExchangeRole {
        self.role
    }

    pub fn is_match(&self, id: u16, role: ExchangeRole) -> bool {
        self.id == id && self.role == role
    }

    pub fn set_exchange_data(&mut self, data: Box<dyn Any>) {
        self.data = Some(data);
    }

    pub fn clear_exchange_data(&mut self) {
        self.data = None;
    }

    pub fn get_and_clear_exchange_data(&mut self) -> Option<Box<dyn Any>> {
        self.data.take()
    }
}

impl fmt::Display for Exchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "exch_id: {:?}, sess_id: {}, role: {:?}, data: {:?}",
            self.id, self.sess_id, self.role, self.data
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
    exchanges: [Option<Exchange>; MAX_EXCHANGES],
}

impl ExchangeMgr {
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    pub fn get(
        &mut self,
        sess_id: u16,
        id: u16,
        role: ExchangeRole,
        create_new: bool,
    ) -> Result<(usize, &mut Exchange), Error> {
        if let Some(index) = self.exchanges.iter().position(|x| {
            if let Some(x) = x {
                x.is_match(id, role)
            } else {
                false
            }
        }) {
            Ok((
                index,
                self.exchanges[index].as_mut().ok_or(Error::NoExchange)?,
            ))
        } else if create_new {
            // If an exchange doesn't exist, create a new one
            info!("Creating new exchange");
            let e = Exchange::new(id, sess_id, role);
            if let Some(index) = self.exchanges.iter().position(|x| x.is_none()) {
                // Return the exchange that was just added
                self.exchanges[index] = Some(e);
                Ok((
                    index,
                    self.exchanges[index].as_mut().ok_or(Error::NoExchange)?,
                ))
            } else {
                Err(Error::NoExchange)
            }
        } else {
            // Got a message that has no matching Exchange object
            Err(Error::NoExchange)
        }
    }
}

impl fmt::Display for ExchangeMgr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{{[")?;
        for s in &self.exchanges {
            if let Some(e) = s {
                writeln!(f, "{{ {}, }},", e)?;
            }
        }
        write!(f, "}}")
    }
}
