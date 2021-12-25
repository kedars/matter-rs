use std::any::Any;

use std::sync::Arc;

use crate::{error::Error, tlv::TLVElement, tlv_writer::TLVWriter, transport::session::Session};

#[derive(PartialEq)]
pub enum TransactionState {
    Ongoing,
    Complete,
}
pub struct Transaction<'a> {
    pub state: TransactionState,
    pub data: Option<Box<dyn Any>>,
    pub session: &'a mut Session,
}

#[derive(Debug, Clone, Copy)]
pub struct CmdPathIb {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub command: u16,
}

pub trait InteractionConsumer {
    fn consume_invoke_cmd(
        &self,
        cmd_path_ib: &CmdPathIb,
        data: TLVElement,
        trans: &mut Transaction,
        tlvwriter: &mut TLVWriter,
    ) -> Result<(), Error>;
}

pub struct InteractionModel {
    consumer: Arc<dyn InteractionConsumer>,
}
pub mod command;
pub mod core;
