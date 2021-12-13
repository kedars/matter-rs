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
    /* As per the spec these should be U16, U32, and U16 respectively */
    pub endpoint: Option<u8>,
    pub cluster: Option<u8>,
    pub command: u8,
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
pub mod demux;
