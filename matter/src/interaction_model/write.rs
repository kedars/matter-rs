use log::error;

use crate::{
    error::Error,
    tlv::{get_root_node_struct, FromTLV, TLVWriter, TagType},
    transport::{packet::Packet, proto_demux::ResponseRequired},
};

use super::{core::OpCode, messages::msg::WriteReq, InteractionModel, Transaction};

impl InteractionModel {
    pub fn handle_write_req(
        &mut self,
        trans: &mut Transaction,
        rx_buf: &[u8],
        proto_tx: &mut Packet,
    ) -> Result<ResponseRequired, Error> {
        proto_tx.set_proto_opcode(OpCode::WriteResponse as u8);

        let mut tw = TLVWriter::new(proto_tx.get_writebuf()?);
        let root = get_root_node_struct(rx_buf)?;
        let write_req = WriteReq::from_tlv(&root)?;
        let supress_response = write_req.supress_response.unwrap_or_default();

        tw.start_struct(TagType::Anonymous)?;
        self.consumer
            .consume_write_attr(&write_req, trans, &mut tw)?;
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
