use crate::{
    error::Error,
    interaction_model::core::OpCode,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::{get_root_node_struct, FromTLV},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{
    messages::msg::{self, ReadReq},
    InteractionModel, Transaction,
};

impl InteractionModel {
    pub fn handle_read_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.proto_opcode = OpCode::ReportData as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(rx_buf)?;
        let read_req = ReadReq::from_tlv(&root)?;

        tw.start_struct(TagType::Anonymous)?;
        self.consumer.consume_read_attr(&read_req, &mut tw)?;
        // Supress response always true for read interaction
        tw.bool(
            TagType::Context(msg::ReportDataTag::SupressResponse as u8),
            true,
        )?;
        tw.end_container()?;

        trans.complete();
        Ok(ResponseRequired::Yes)
    }
}
