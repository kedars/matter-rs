use log::info;

use crate::{
    error::Error,
    interaction_model::core::OpCode,
    proto_demux::{ProtoTx, ResponseRequired},
    tlv::{get_root_node_struct, print_tlv_list},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

use super::{InteractionModel, Transaction};

// TODO: This is different between the spec and C++
enum Tag {
    AttrRequests = 0,
    _DataVerFilters = 1,
    _EventRequests = 2,
    _EventFilters = 3,
    FabricFiltered = 4,
}

pub mod attr_path {

    use crate::{
        error::Error,
        tlv::TLVElement,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };
    use log::error;

    const TAG_ENABLE_TAG_COMPRESSION: u8 = 0;
    const TAG_NODE: u8 = 1;
    const TAG_ENDPOINT: u8 = 2;
    const TAG_CLUSTER: u8 = 3;
    const TAG_ATTRIBUTE: u8 = 4;
    const TAG_LIST_INDEX: u8 = 5;

    #[derive(Default, Clone, Copy, Debug)]
    pub struct Ib {
        pub tag_compression: bool,
        pub node: Option<u64>,
        pub endpoint: Option<u16>,
        pub cluster: Option<u32>,
        pub attribute: Option<u16>,
        pub list_index: Option<u16>,
    }

    impl Ib {
        pub fn new(endpoint: u16, cluster: u32, attribute: u16) -> Self {
            Self {
                endpoint: Some(endpoint),
                cluster: Some(cluster),
                attribute: Some(attribute),
                ..Default::default()
            }
        }

        pub fn from_tlv(attr_path: &TLVElement) -> Result<Self, Error> {
            let mut ib = Ib::default();

            let iter = attr_path.iter().ok_or(Error::Invalid)?;
            for i in iter {
                match i.get_tag() {
                    TagType::Context(TAG_ENABLE_TAG_COMPRESSION) => {
                        error!("Tag Compression not yet supported");
                        ib.tag_compression = i.get_bool()?
                    }
                    TagType::Context(TAG_NODE) => ib.node = i.get_u32().map(|a| a as u64).ok(),
                    TagType::Context(TAG_ENDPOINT) => {
                        ib.endpoint = i.get_u8().map(|a| a as u16).ok()
                    }
                    TagType::Context(TAG_CLUSTER) => ib.cluster = i.get_u8().map(|a| a as u32).ok(),
                    TagType::Context(TAG_ATTRIBUTE) => {
                        ib.attribute = i.get_u8().map(|a| a as u16).ok()
                    }
                    TagType::Context(TAG_LIST_INDEX) => ib.list_index = i.get_u16().ok(),
                    _ => (),
                }
            }
            Ok(ib)
        }
    }

    impl ToTLV for Ib {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_list(tag_type)?;
            if let Some(v) = self.endpoint {
                tw.put_u16(TagType::Context(TAG_ENDPOINT), v)?;
            }
            if let Some(v) = self.cluster {
                tw.put_u32(TagType::Context(TAG_CLUSTER), v)?;
            }
            if let Some(v) = self.attribute {
                tw.put_u16(TagType::Context(TAG_ATTRIBUTE), v)?;
            }
            tw.put_end_container()
        }
    }
}

mod report_data {
    // TODO: Differs from spec
    pub enum Tag {
        _SubscriptionId = 0,
        AttributeReportIb = 1,
        _EventReport = 2,
        _MoreChunkedMsgs = 3,
        SupressResponse = 4,
    }
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

        print_tlv_list(rx_buf);
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
