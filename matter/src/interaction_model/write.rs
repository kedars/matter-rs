use log::error;

use crate::{
    error::Error,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::get_root_node_struct,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{core::OpCode, messages::msg, InteractionModel, Transaction};

impl InteractionModel {
    pub fn handle_write_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.proto_opcode = OpCode::WriteResponse as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(rx_buf)?;
        // TODO: This is found in the spec, but not in the C++ implementation
        let fab_scoped = false;
        let supress_response = if root
            .find_tag(msg::WriteReqTag::SuppressResponse as u32)
            .is_ok()
        {
            true
        } else {
            false
        };

        tw.start_struct(TagType::Anonymous)?;

        let attr_list_iter = root.find_tag(msg::WriteReqTag::WriteRequests as u32);
        if attr_list_iter.is_ok() {
            tw.start_array(TagType::Context(msg::WriteRespTag::WriteResponses as u8))?;
            self.consumer
                .consume_write_attr(attr_list_iter?, fab_scoped, &mut tw)?;
            tw.end_container()?;
        }

        tw.end_container()?;
        trans.complete();
        if supress_response {
            error!("Supress response is set, is this the expected handling?");
            Ok(ResponseRequired::No)
        } else {
            Ok(ResponseRequired::Yes)
        }
    }
}
