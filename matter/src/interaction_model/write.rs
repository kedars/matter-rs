use log::{error, info};

use crate::{
    error::Error,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::get_root_node_struct,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{core::OpCode, messages::ib, InteractionModel, Transaction};

// TODO: This is different between the spec and C++
enum Tag {
    SuppressResponse = 0,
    _TimedRequest = 1,
    WriteRequests = 2,
    _MoreChunkedMsgs = 3,
    FabricFiltered = 4,
}

impl InteractionModel {
    pub fn handle_write_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut ProtoTx,
    ) -> Result<ResponseRequired, Error> {
        info!("In Write Req");
        proto_tx.proto_opcode = OpCode::WriteResponse as u8;

        let mut tw = TLVWriter::new(&mut proto_tx.write_buf);
        let root = get_root_node_struct(rx_buf)?;
        let fab_scoped = root.find_tag(Tag::FabricFiltered as u32)?.get_bool()?;
        let supress_response = if root.find_tag(Tag::SuppressResponse as u32).is_ok() {
            true
        } else {
            false
        };

        tw.put_start_struct(TagType::Anonymous)?;

        let attr_list_iter = root.find_tag(Tag::WriteRequests as u32);
        if attr_list_iter.is_ok() {
            tw.put_start_array(TagType::Context(ib::WriteResponseTag::WriteResponses as u8))?;
            self.consumer
                .consume_write_attr(attr_list_iter?, fab_scoped, &mut tw)?;
            tw.put_end_container()?;
        }

        tw.put_end_container()?;
        trans.complete();
        if supress_response {
            error!("Supress response is set, is this the expected handling?");
            Ok(ResponseRequired::No)
        } else {
            Ok(ResponseRequired::Yes)
        }
    }
}
