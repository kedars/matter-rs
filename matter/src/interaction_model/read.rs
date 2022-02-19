use log::info;

use crate::{
    error::Error,
    interaction_model::core::OpCode,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::get_root_node_struct,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{messages::report_data, InteractionModel, Transaction};

// TODO: This is different between the spec and C++
enum Tag {
    AttrRequests = 0,
    _DataVerFilters = 1,
    _EventRequests = 2,
    _EventFilters = 3,
    FabricFiltered = 4,
}

impl InteractionModel {
    pub fn handle_read_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In Read Req");
        proto_tx.proto_opcode = OpCode::ReportData as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(rx_buf)?;
        let fab_scoped = root.find_tag(Tag::FabricFiltered as u32)?.get_bool()?;

        tw.put_start_struct(TagType::Anonymous)?;

        let attr_list_iter = root.find_tag(Tag::AttrRequests as u32);
        if attr_list_iter.is_ok() {
            tw.put_start_array(TagType::Context(report_data::Tag::AttributeReportIb as u8))?;
            self.consumer
                .consume_read_attr(attr_list_iter?, fab_scoped, &mut tw)?;
            tw.put_end_container()?;
        }

        // Supress response always true for read interaction
        tw.put_bool(
            TagType::Context(report_data::Tag::SupressResponse as u8),
            true,
        )?;
        tw.put_end_container()?;
        trans.complete();
        Ok(ResponseRequired::Yes)
    }
}
