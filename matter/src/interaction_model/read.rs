use log::error;

use crate::{
    error::Error,
    interaction_model::core::OpCode,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::get_root_node_struct,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{messages::msg, InteractionModel, Transaction};

// TODO: This is different between the spec and C++

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
        let fab_scoped = root
            .find_tag(msg::ReadReqTag::FabricFiltered as u32)?
            .get_bool()?;

        tw.start_struct(TagType::Anonymous)?;

        let attr_list_iter = root.find_tag(msg::ReadReqTag::AttrRequests as u32);
        if attr_list_iter.is_ok() {
            let dataver_filters_iter = root.find_tag(msg::ReadReqTag::DataVerFilters as u32);
            if dataver_filters_iter.is_ok() {
                error!("Data version filters aren't yet supported");
            }

            tw.start_array(TagType::Context(msg::ReportDataTag::AttributeReports as u8))?;
            self.consumer
                .consume_read_attr(attr_list_iter?, fab_scoped, &mut tw)?;
            tw.end_container()?;
        }

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
