use std::any::Any;

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ExchangeRole {
    Initiator = 0,
    Responder = 1,
}

#[derive(Debug)]
pub struct Exchange {
    id: u16,
    role: ExchangeRole,
    // The spec only allows a single pending ACK per exchange
    pending_ack: Option<u32>,
    // Currently I see this primarily used in PASE and CASE. If that is the limited use
    // of this, we might move this into a separate data structure, so as not to burden
    // all 'exchanges'.
    data: Option<Box<dyn Any>>,
}

impl Exchange {
    pub fn new(id: u16, role: ExchangeRole) -> Exchange {
        Exchange {
            id,
            role,
            pending_ack: None,
            data: None,
        }
    }

    pub fn is_match(&self, id: u16, role: ExchangeRole) -> bool {
        self.id == id && self.role == role
    }

    pub fn ack_pending(&mut self, ack_ctr: u32) {
        self.pending_ack = Some(ack_ctr);
    }

    pub fn is_ack_pending(&self) -> Option<u32> {
        self.pending_ack
    }

    pub fn clear_ack_pending(&mut self) {
        self.pending_ack = None;
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
