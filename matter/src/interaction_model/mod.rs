use std::any::Any;

use crate::{error::Error, tlv::TLVWriter, transport::session::Session};

use self::messages::msg::{InvReq, ReadReq, WriteReq};

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

pub trait InteractionConsumer {
    fn consume_invoke_cmd(
        &self,
        req: &InvReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;

    fn consume_read_attr(
        &self,
        req: &ReadReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;

    fn consume_write_attr(
        &self,
        req: &WriteReq,
        trans: &mut Transaction,
        tw: &mut TLVWriter,
    ) -> Result<(), Error>;
}

pub struct InteractionModel {
    consumer: Box<dyn InteractionConsumer>,
}
pub mod command;
pub mod core;
pub mod messages;
pub mod read;
pub mod write;
