use super::core::OpCode;
use super::messages::ib;
use super::messages::msg;
use super::messages::msg::InvReq;
use super::InteractionModel;
use super::Transaction;
use crate::{
    error::*,
    tlv::{get_root_node_struct, print_tlv_list, FromTLV, TLVElement, TLVWriter, TagType},
    transport::{packet::Packet, proto_demux::ResponseRequired},
};
use log::error;

#[macro_export]
macro_rules! cmd_enter {
    ($e:expr) => {{
        use colored::Colorize;
        info! {"{} {}", "Handling Command".cyan(), $e.cyan()}
    }};
}

pub struct CommandReq<'a, 'b, 'c, 'd> {
    pub cmd: ib::CmdPath,
    pub data: TLVElement<'a>,
    pub resp: &'a mut TLVWriter<'b, 'c>,
    pub trans: &'a mut Transaction<'d>,
}

impl InteractionModel {
    pub fn handle_invoke_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::InvokeResponse as u8);

        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let root = get_root_node_struct(rx_buf)?;
        let inv_req = InvReq::from_tlv(&root)?;

        tw.start_struct(TagType::Anonymous)?;
        // Suppress Response -> TODO: Need to revisit this for cases where we send a command back
        tw.bool(
            TagType::Context(msg::InvRespTag::SupressResponse as u8),
            false,
        )?;

        self.consumer
            .consume_invoke_cmd(&inv_req, trans, &mut tw)
            .map_err(|e| {
                error!("Error in handling command: {:?}", e);
                print_tlv_list(rx_buf);
                e
            })?;
        tw.end_container()?;
        Ok(ResponseRequired::Yes)
    }
}
