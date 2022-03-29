use log::error;

use crate::{
    error::Error,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::{get_root_node_struct, FromTLV},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{core::OpCode, messages::msg::WriteReq, InteractionModel, Transaction};

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
        let write_req = WriteReq::from_tlv(&root)?;
        // TODO: This is found in the spec, but not in the C++ implementation
        let _fab_scoped = false;
        let supress_response = if write_req.supress_response.is_some() {
            true
        } else {
            false
        };

        tw.start_struct(TagType::Anonymous)?;
        self.consumer.consume_write_attr(&write_req, &mut tw)?;
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
