use std::any::Any;

use std::sync::Arc;

use crate::{error::Error, tlv::TLVElement, tlv_writer::TLVWriter};

#[derive(PartialEq)]
pub enum TransactionState {
    Ongoing,
    Complete,
}
pub struct Transaction {
    pub state: TransactionState,
    pub data: Option<Box<dyn Any>>,
}

#[derive(Debug)]
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
