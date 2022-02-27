// A generic path with endpoint, clusters, and a leaf
// The leaf could be command, attribute, event
#[derive(Default, Clone, Copy, Debug)]
pub struct GenericPath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub leaf: Option<u32>,
}

pub mod command_response {
    use crate::{
        error::Error,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::{command_path, status};

    #[derive(Debug, Clone, Copy)]
    pub enum Ib<F>
    where
        F: Fn(&mut TLVWriter) -> Result<(), Error>,
    {
        CommandData(command_path::Ib, F),
        CommandStatus(command_path::Ib, status::Ib, F),
    }

    pub fn dummy(_t: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    impl<F: Fn(&mut TLVWriter) -> Result<(), Error>> ToTLV for Ib<F> {
        fn to_tlv(self: &Ib<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                Ib::CommandData(cmd_path, data_cb) => {
                    tw.put_start_struct(TagType::Context(0))?;
                    tw.put_object(TagType::Context(0), cmd_path)?;
                    tw.put_start_struct(TagType::Context(1))?;
                    data_cb(tw)?;
                    tw.put_end_container()?;
                }
                Ib::CommandStatus(cmd_path, status, _) => {
                    tw.put_start_struct(TagType::Context(1))?;
                    tw.put_object(TagType::Context(0), cmd_path)?;
                    tw.put_object(TagType::Context(1), status)?;
                }
            }
            tw.put_end_container()?;
            tw.put_end_container()
        }
    }
}

pub mod status {
    use crate::{
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    enum Tag {
        Status = 0,
        ClusterStatus = 1,
    }

    #[derive(Debug, Clone, Copy)]
    pub struct Ib {
        status: IMStatusCode,
        cluster_status: u32,
    }

    impl Ib {
        pub fn new(status: IMStatusCode, cluster_status: u32) -> Ib {
            Ib {
                status,
                cluster_status,
            }
        }
    }

    impl ToTLV for Ib {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            tw.put_u32(TagType::Context(Tag::Status as u8), self.status as u32)?;
            tw.put_u32(
                TagType::Context(Tag::ClusterStatus as u8),
                self.cluster_status,
            )?;
            tw.put_end_container()
        }
    }
}

pub mod attr_response {
    use crate::{
        error::Error,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::{attr_data, attr_status};

    #[derive(Debug, Clone, Copy)]
    pub enum Ib<F>
    where
        F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>,
    {
        AttrData(attr_data::IbOut<F>),
        AttrStatus(attr_status::Ib, F),
    }

    pub fn dummy(_a: TagType, _t: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> ToTLV for Ib<F> {
        fn to_tlv(self: &Ib<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                Ib::AttrData(data) => {
                    // In this case, we'll have to add the AttributeDataIb
                    tw.put_object(TagType::Context(1), data)?;
                }
                Ib::AttrStatus(status, _) => {
                    // In this case, we'll have to add the AttributeStatusIb
                    tw.put_object(TagType::Context(0), status)?;
                }
            }
            tw.put_end_container()
        }
    }
}

pub mod attr_data {
    use crate::{
        error::Error,
        tlv::TLVElement,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::attr_path;

    use log::error;

    #[derive(Debug, Clone, Copy)]
    pub struct IbIn<'a> {
        pub path: attr_path::Ib,
        pub data: TLVElement<'a>,
    }

    pub enum Tag {
        DataVersion = 0,
        Path = 1,
        Data = 2,
    }

    impl<'a> IbIn<'a> {
        pub fn from_tlv(attr_data: &TLVElement<'a>) -> Result<Self, Error> {
            let data_version = attr_data.find_tag(Tag::DataVersion as u32);
            if data_version.is_ok() {
                let _data_version = data_version?.get_u8()?;
                error!("Data Version handling not yet supported");
            }
            let path = attr_data.find_tag(Tag::Path as u32)?;
            let path = attr_path::Ib::from_tlv(&path)?;
            let data = attr_data.find_tag(Tag::Data as u32)?;
            Ok(Self { path, data })
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct IbOut<F>
    where
        F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>,
    {
        path: attr_path::Ib,
        data: F,
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> IbOut<F> {
        pub fn new(path: attr_path::Ib, data: F) -> Self {
            Self { path, data }
        }
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> ToTLV for IbOut<F> {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            tw.put_object(TagType::Context(Tag::Path as u8), &self.path)?;
            (self.data)(TagType::Context(Tag::Data as u8), tw)?;
            tw.put_end_container()
        }
    }
}

pub mod attr_status {
    use crate::{
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::{attr_path, status, GenericPath};

    #[derive(Debug, Clone, Copy)]
    pub struct Ib {
        path: attr_path::Ib,
        status: status::Ib,
    }

    impl Ib {
        pub fn new(path: &GenericPath, status: IMStatusCode, cluster_status: u32) -> Self {
            Self {
                path: attr_path::Ib::new(path),
                status: status::Ib::new(status, cluster_status),
            }
        }
    }

    impl ToTLV for Ib {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            // Attribute Status IB
            tw.put_object(TagType::Context(0), &self.path)?;
            // Status IB
            tw.put_object(TagType::Context(1), &self.status)?;
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

            let iter = attr_path.confirm_list()?.iter().ok_or(Error::Invalid)?;
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
                        ib.path.leaf = i.get_u16().map(|a| a as u32).ok()
                    }
                    TagType::Context(TAG_LIST_INDEX) => ib.list_index = i.get_u16().ok(),
                    _ => error!("Unsupported tag"),
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

pub mod command_path {
    use crate::{
        error::Error,
        tlv::TLVElement,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::GenericPath;

    use log::error;

    #[derive(Default, Debug, Copy, Clone)]
    pub struct Ib {
        pub path: GenericPath,
    }

    const TAG_ENDPOINT: u8 = 0;
    const TAG_CLUSTER: u8 = 1;
    const TAG_COMMAND: u8 = 2;

    #[macro_export]
    macro_rules! command_path_ib {
        ($endpoint:literal,$cluster:ident,$command:ident) => {{
            use crate::interaction_model::messages::command_path::Ib;
            Ib {
                path: GenericPath {
                    endpoint: Some($endpoint),
                    cluster: Some($cluster),
                    leaf: Some($command as u32),
                },
            }
        }};
    }

    impl Ib {
        pub fn from_tlv(cmd_path: &TLVElement) -> Result<Self, Error> {
            let mut ib = Ib::default();

            let iter = cmd_path.iter().ok_or(Error::Invalid)?;
            for i in iter {
                match i.get_tag() {
                    TagType::Context(TAG_ENDPOINT) => {
                        ib.path.endpoint = i.get_u8().map(|a| a as u16).ok()
                    }
                    TagType::Context(TAG_CLUSTER) => {
                        ib.path.cluster = i.get_u8().map(|a| a as u32).ok()
                    }
                    TagType::Context(TAG_COMMAND) => {
                        ib.path.leaf = i.get_u8().map(|a| a as u32).ok()
                    }
                    _ => error!("Unsupported tag"),
                }
            }
            if ib.path.leaf.is_none() {
                error!("Wildcard command parameter not supported");
                Err(Error::CommandNotFound)
            } else {
                Ok(ib)
            }
        }
    }

    impl ToTLV for Ib {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_list(tag_type)?;
            if let Some(endpoint) = self.path.endpoint {
                tw.put_u16(TagType::Context(TAG_ENDPOINT), endpoint)?;
            }
            if let Some(cluster) = self.path.cluster {
                tw.put_u32(TagType::Context(TAG_CLUSTER), cluster)?;
            }
            if let Some(v) = self.path.leaf {
                tw.put_u16(TagType::Context(TAG_COMMAND), v as u16)?;
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

pub mod write_response {
    pub enum Tag {
        WriteResponses = 0,
    }
}
