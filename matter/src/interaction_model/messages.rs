// A generic path with endpoint, clusters, and a leaf
// The leaf could be command, attribute, event
#[derive(Default, Clone, Copy, Debug)]
pub struct GenericPath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub leaf: Option<u32>,
}

pub mod attr_response {
    use crate::{
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::attr_path;

    #[derive(Debug, Clone, Copy)]
    pub enum Ib<F>
    where
        F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>,
    {
        AttrData(attr_path::Ib, F),
        AttrStatus(attr_path::Ib, IMStatusCode, u16, F),
    }

    pub fn dummy(_a: TagType, _t: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> ToTLV for Ib<F> {
        fn to_tlv(self: &Ib<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                Ib::AttrData(path, f) => {
                    tw.put_start_struct(TagType::Context(1))?;
                    tw.put_object(TagType::Context(1), path)?;
                    f(TagType::Context(2), tw)?;
                    tw.put_end_container()?;
                }
                Ib::AttrStatus(path, status, cluster_status, _f) => {
                    // In this case, we'll have to add the AttributeStatusIb
                    tw.put_start_struct(TagType::Context(0))?;
                    // Attribute Status IB
                    tw.put_object(TagType::Context(0), path)?;
                    // Status IB
                    tw.put_start_struct(TagType::Context(1))?;
                    tw.put_u16(TagType::Context(0), *status as u16)?;
                    tw.put_u16(TagType::Context(1), *cluster_status)?;
                    tw.put_end_container()?;
                    tw.put_end_container()?;
                }
            }
            tw.put_end_container()
        }
    }
}

pub mod attr_path {

    use crate::{
        error::Error,
        tlv::TLVElement,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };
    use log::error;

    use super::GenericPath;

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
        pub path: GenericPath,
        pub list_index: Option<u16>,
    }

    impl Ib {
        pub fn new(path: &GenericPath) -> Self {
            Self {
                path: *path,
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
                        ib.path.endpoint = i.get_u8().map(|a| a as u16).ok()
                    }
                    TagType::Context(TAG_CLUSTER) => {
                        ib.path.cluster = i.get_u8().map(|a| a as u32).ok()
                    }
                    TagType::Context(TAG_ATTRIBUTE) => {
                        ib.path.leaf = i.get_u8().map(|a| a as u32).ok()
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
            if let Some(v) = self.path.endpoint {
                tw.put_u16(TagType::Context(TAG_ENDPOINT), v)?;
            }
            if let Some(v) = self.path.cluster {
                tw.put_u32(TagType::Context(TAG_CLUSTER), v)?;
            }
            if let Some(v) = self.path.leaf {
                tw.put_u16(TagType::Context(TAG_ATTRIBUTE), v as u16)?;
            }
            tw.put_end_container()
        }
    }
}

pub mod report_data {
    // TODO: Differs from spec
    pub enum Tag {
        _SubscriptionId = 0,
        AttributeReportIb = 1,
        _EventReport = 2,
        _MoreChunkedMsgs = 3,
        SupressResponse = 4,
    }
}
