// A generic path with endpoint, clusters, and a leaf
// The leaf could be command, attribute, event
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct GenericPath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub leaf: Option<u32>,
}

pub mod msg {
    pub enum InvResponseTag {
        SupressResponse = 0,
        InvokeResponses = 1,
    }
}

pub mod ib {
    use crate::{
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv::TLVElement,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };
    use log::error;
    use num_derive::FromPrimitive;

    use super::GenericPath;

    // Command Response
    #[derive(Debug, Clone, Copy)]
    pub enum InvResponseOut<F>
    where
        F: Fn(&mut TLVWriter) -> Result<(), Error>,
    {
        Cmd(CmdPath, F),
        Status(CmdPath, Status, F),
    }

    #[derive(FromPrimitive)]
    enum InvResponseTag {
        Cmd = 0,
        Status = 1,
    }

    enum CmdDataTag {
        Path = 0,
        Data = 1,
    }

    enum CmdStatusTag {
        Path = 0,
        Status = 1,
    }

    pub fn cmd_resp_dummy(_t: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    impl<F: Fn(&mut TLVWriter) -> Result<(), Error>> ToTLV for InvResponseOut<F> {
        fn to_tlv(
            self: &InvResponseOut<F>,
            tw: &mut TLVWriter,
            tag_type: TagType,
        ) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                InvResponseOut::Cmd(cmd_path, data_cb) => {
                    tw.put_start_struct(TagType::Context(InvResponseTag::Cmd as u8))?;
                    tw.put_object(TagType::Context(CmdDataTag::Path as u8), cmd_path)?;
                    // TODO: We are cheating here a little bit. This following 'Data' need
                    // not be a 'structure'. Somebody could directly embed u8 at the tag
                    // 'CmdDataTag::Data'. We will have to modify this (and all the callers)
                    // when we stumble across that scenario
                    tw.put_start_struct(TagType::Context(CmdDataTag::Data as u8))?;
                    data_cb(tw)?;
                    tw.put_end_container()?;
                }
                InvResponseOut::Status(cmd_path, status, _) => {
                    tw.put_start_struct(TagType::Context(InvResponseTag::Status as u8))?;
                    tw.put_object(TagType::Context(CmdStatusTag::Path as u8), cmd_path)?;
                    tw.put_object(TagType::Context(CmdStatusTag::Status as u8), status)?;
                }
            }
            tw.put_end_container()?;
            tw.put_end_container()
        }
    }

    pub enum InvResponseIn<'a> {
        Cmd(CmdPath, TLVElement<'a>),
        Status(CmdPath, Status),
    }

    impl<'a> InvResponseIn<'a> {
        pub fn from_tlv(resp: &TLVElement<'a>) -> Result<Self, Error> {
            let resp = resp
                .confirm_struct()?
                .iter()
                .ok_or(Error::Invalid)?
                .next()
                .ok_or(Error::Invalid)?;
            let tag = match resp.get_tag() {
                TagType::Context(a) => a,
                _ => {
                    return Err(Error::TLVTypeMismatch);
                }
            };

            match num::FromPrimitive::from_u8(tag).ok_or(Error::Invalid)? {
                InvResponseTag::Cmd => {
                    let cmd_path = resp.find_tag(CmdDataTag::Path as u32)?;
                    let data = resp.find_tag(CmdDataTag::Data as u32)?;
                    Ok(InvResponseIn::Cmd(CmdPath::from_tlv(&cmd_path)?, data))
                }
                InvResponseTag::Status => {
                    let cmd_path = resp.find_tag(CmdStatusTag::Path as u32)?;
                    let status = resp.find_tag(CmdStatusTag::Status as u32)?;
                    Ok(InvResponseIn::Status(
                        CmdPath::from_tlv(&cmd_path)?,
                        Status::from_tlv(&status)?,
                    ))
                }
            }
        }
    }

    // Status
    #[derive(Debug, Clone, Copy)]
    pub struct Status {
        pub status: IMStatusCode,
        pub cluster_status: u16,
    }

    enum StatusTag {
        Status = 0,
        ClusterStatus = 1,
    }

    impl Status {
        pub fn new(status: IMStatusCode, cluster_status: u16) -> Status {
            Status {
                status,
                cluster_status,
            }
        }
    }

    impl ToTLV for Status {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            tw.put_u16(
                TagType::Context(StatusTag::Status as u8),
                self.status as u16,
            )?;
            tw.put_u16(
                TagType::Context(StatusTag::ClusterStatus as u8),
                self.cluster_status,
            )?;
            tw.put_end_container()
        }
    }

    impl Status {
        pub fn from_tlv(status_tlv: &TLVElement) -> Result<Self, Error> {
            let status = status_tlv.find_tag(StatusTag::Status as u32)?.get_u16()?;
            let cluster_status = status_tlv
                .find_tag(StatusTag::ClusterStatus as u32)?
                .get_u16()?;
            Ok(Self {
                status: num::FromPrimitive::from_u16(status).ok_or(Error::Invalid)?,
                cluster_status,
            })
        }
    }

    // Attribute Response
    #[derive(Debug, Clone, Copy)]
    pub enum AttrResp<F>
    where
        F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>,
    {
        Data(AttrDataOut<F>),
        Status(AttrStatus, F),
    }

    pub fn attr_resp_dummy(_a: TagType, _t: &mut TLVWriter) -> Result<(), Error> {
        Ok(())
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> ToTLV for AttrResp<F> {
        fn to_tlv(self: &AttrResp<F>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                AttrResp::Data(data) => {
                    // In this case, we'll have to add the AttributeDataIb
                    tw.put_object(TagType::Context(1), data)?;
                }
                AttrResp::Status(status, _) => {
                    // In this case, we'll have to add the AttributeStatusIb
                    tw.put_object(TagType::Context(0), status)?;
                }
            }
            tw.put_end_container()
        }
    }

    // Attribute Data
    #[derive(Debug, Clone, Copy)]
    pub struct AttrDataIn<'a> {
        pub path: AttrPath,
        pub data: TLVElement<'a>,
    }

    pub enum Tag {
        DataVersion = 0,
        Path = 1,
        Data = 2,
    }

    impl<'a> AttrDataIn<'a> {
        pub fn from_tlv(attr_data: &TLVElement<'a>) -> Result<Self, Error> {
            let data_version = attr_data.find_tag(Tag::DataVersion as u32);
            if data_version.is_ok() {
                let _data_version = data_version?.get_u8()?;
                error!("Data Version handling not yet supported");
            }
            let path = attr_data.find_tag(Tag::Path as u32)?;
            let path = AttrPath::from_tlv(&path)?;
            let data = attr_data.find_tag(Tag::Data as u32)?;
            Ok(Self { path, data })
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct AttrDataOut<F>
    where
        F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>,
    {
        data_ver: u32,
        path: AttrPath,
        data: F,
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> AttrDataOut<F> {
        pub fn new(data_ver: u32, path: AttrPath, data: F) -> Self {
            Self {
                data_ver,
                path,
                data,
            }
        }
    }

    impl<F: Fn(TagType, &mut TLVWriter) -> Result<(), Error>> ToTLV for AttrDataOut<F> {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            tw.put_u32(TagType::Context(Tag::DataVersion as u8), self.data_ver)?;
            tw.put_object(TagType::Context(Tag::Path as u8), &self.path)?;
            (self.data)(TagType::Context(Tag::Data as u8), tw)?;
            tw.put_end_container()
        }
    }

    // Attribute Status
    #[derive(Debug, Clone, Copy)]
    pub struct AttrStatus {
        path: AttrPath,
        status: super::ib::Status,
    }

    impl AttrStatus {
        pub fn new(path: &GenericPath, status: IMStatusCode, cluster_status: u16) -> Self {
            Self {
                path: AttrPath::new(path),
                status: super::ib::Status::new(status, cluster_status),
            }
        }
    }

    impl ToTLV for AttrStatus {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            // Attribute Status IB
            tw.put_object(TagType::Context(0), &self.path)?;
            // Status IB
            tw.put_object(TagType::Context(1), &self.status)?;
            tw.put_end_container()
        }
    }

    // Attribute Path
    #[derive(Default, Clone, Copy, Debug)]
    pub struct AttrPath {
        pub tag_compression: bool,
        pub node: Option<u64>,
        pub path: GenericPath,
        pub list_index: Option<u16>,
    }

    #[derive(FromPrimitive)]
    pub enum AttrPathTag {
        TagCompression = 0,
        Node = 1,
        Endpoint = 2,
        Cluster = 3,
        Attribute = 4,
        ListIndex = 5,
    }

    impl AttrPath {
        pub fn new(path: &GenericPath) -> Self {
            Self {
                path: *path,
                ..Default::default()
            }
        }

        pub fn from_tlv(attr_path: &TLVElement) -> Result<Self, Error> {
            let mut ib = AttrPath::default();

            let iter = attr_path.confirm_list()?.iter().ok_or(Error::Invalid)?;
            for i in iter {
                match i.get_tag() {
                    TagType::Context(t) => match num::FromPrimitive::from_u8(t)
                        .ok_or(Error::Invalid)?
                    {
                        AttrPathTag::TagCompression => {
                            error!("Tag Compression not yet supported");
                            ib.tag_compression = i.get_bool()?
                        }
                        AttrPathTag::Node => ib.node = i.get_u32().map(|a| a as u64).ok(),
                        AttrPathTag::Endpoint => {
                            ib.path.endpoint = i.get_u16().map(|a| a as u16).ok()
                        }
                        AttrPathTag::Cluster => {
                            ib.path.cluster = i.get_u32().map(|a| a as u32).ok()
                        }
                        AttrPathTag::Attribute => ib.path.leaf = i.get_u16().map(|a| a as u32).ok(),
                        AttrPathTag::ListIndex => ib.list_index = i.get_u16().ok(),
                    },
                    _ => error!("Unsupported tag"),
                }
            }
            Ok(ib)
        }
    }

    impl ToTLV for AttrPath {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_list(tag_type)?;
            if let Some(v) = self.path.endpoint {
                tw.put_u16(TagType::Context(AttrPathTag::Endpoint as u8), v)?;
            }
            if let Some(v) = self.path.cluster {
                tw.put_u32(TagType::Context(AttrPathTag::Cluster as u8), v)?;
            }
            if let Some(v) = self.path.leaf {
                tw.put_u16(TagType::Context(AttrPathTag::Attribute as u8), v as u16)?;
            }
            tw.put_end_container()
        }
    }

    // Command Path
    #[derive(Default, Debug, Copy, Clone, PartialEq)]
    pub struct CmdPath {
        pub path: GenericPath,
    }

    #[derive(FromPrimitive)]
    pub enum CmdPathTag {
        Endpoint = 0,
        Cluster = 1,
        Command = 2,
    }

    #[macro_export]
    macro_rules! command_path_ib {
        ($endpoint:literal,$cluster:ident,$command:ident) => {{
            use $crate::interaction_model::messages::{ib::CmdPath, GenericPath};
            CmdPath {
                path: GenericPath {
                    endpoint: Some($endpoint),
                    cluster: Some($cluster),
                    leaf: Some($command as u32),
                },
            }
        }};
    }

    impl CmdPath {
        pub fn new(endpoint: Option<u16>, cluster: Option<u32>, command: Option<u16>) -> Self {
            Self {
                path: GenericPath {
                    endpoint,
                    cluster,
                    leaf: command.map(|a| a as u32),
                },
            }
        }

        pub fn from_tlv(cmd_path: &TLVElement) -> Result<Self, Error> {
            let mut ib = CmdPath::default();

            let iter = cmd_path.iter().ok_or(Error::Invalid)?;
            for i in iter {
                match i.get_tag() {
                    TagType::Context(t) => {
                        match num::FromPrimitive::from_u8(t).ok_or(Error::Invalid)? {
                            CmdPathTag::Endpoint => {
                                ib.path.endpoint = i.get_u16().map(|a| a as u16).ok()
                            }
                            CmdPathTag::Cluster => {
                                ib.path.cluster = i.get_u32().map(|a| a as u32).ok()
                            }
                            CmdPathTag::Command => {
                                ib.path.leaf = i.get_u32().map(|a| a as u32).ok()
                            }
                        }
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

    impl ToTLV for CmdPath {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_list(tag_type)?;
            if let Some(endpoint) = self.path.endpoint {
                tw.put_u16(TagType::Context(CmdPathTag::Endpoint as u8), endpoint)?;
            }
            if let Some(cluster) = self.path.cluster {
                tw.put_u32(TagType::Context(CmdPathTag::Cluster as u8), cluster)?;
            }
            if let Some(v) = self.path.leaf {
                tw.put_u16(TagType::Context(CmdPathTag::Command as u8), v as u16)?;
            }
            tw.put_end_container()
        }
    }

    // Report Data
    // TODO: Differs from spec
    pub enum ReportDataTag {
        _SubscriptionId = 0,
        AttributeReportIb = 1,
        _EventReport = 2,
        _MoreChunkedMsgs = 3,
        SupressResponse = 4,
    }

    // Write Response
    pub enum WriteResponseTag {
        WriteResponses = 0,
    }
}
