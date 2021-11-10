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
}

impl Exchange {
    pub fn new(id: u16, role: ExchangeRole) -> Exchange {
        Exchange {
            id,
            role,
            pending_ack: None,
        }
    }

    pub fn is_match(&self, id: u16, role: ExchangeRole) -> bool {
        self.id == id && self.role == role
    }

    pub fn ack_pending(&mut self, ack_ctr: u32) {
        self.pending_ack = Some(ack_ctr);
    }

    pub fn is_ack_pending(&self) -> Option<u32> {
        return self.pending_ack;
    }

    pub fn clear_ack_pending(&mut self) {
        self.pending_ack = None;
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
