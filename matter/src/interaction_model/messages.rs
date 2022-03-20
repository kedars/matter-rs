use crate::error::Error;

// A generic path with endpoint, clusters, and a leaf
// The leaf could be command, attribute, event
#[derive(Default, Clone, Copy, Debug, PartialEq)]
pub struct GenericPath {
    pub endpoint: Option<u16>,
    pub cluster: Option<u32>,
    pub leaf: Option<u32>,
}

impl GenericPath {
    pub fn new(endpoint: Option<u16>, cluster: Option<u32>, leaf: Option<u32>) -> Self {
        Self {
            endpoint,
            cluster,
            leaf,
        }
    }

    /// Returns Ok, if the path is non wildcard, otherwise returns an error
    pub fn not_wildcard(&self) -> Result<(u16, u32, u32), Error> {
        match *self {
            GenericPath {
                endpoint: Some(e),
                cluster: Some(c),
                leaf: Some(l),
            } => Ok((e, c, l)),
            _ => Err(Error::Invalid),
        }
    }
}

pub mod msg {
    use crate::{
        error::Error,
        tlv_common::TagType,
        tlv_writer::{TLVWriter, ToTLV},
    };

    use super::ib::AttrPath;

    pub enum InvResponseTag {
        SupressResponse = 0,
        InvokeResponses = 1,
    }

    pub enum InvRequestTag {
        SupressResponse = 0,
        TimedReq = 1,
        InvokeRequests = 2,
    }

    pub enum ReadReqTag {
        AttrRequests = 0,
        DataVerFilters = 1,
        _EventRequests = 2,
        _EventFilters = 3,
        FabricFiltered = 4,
    }

    #[derive(Default)]
    pub struct ReadReq<'a> {
        attr_requests: Option<&'a [AttrPath]>,
        fabric_filtered: bool,
    }

    impl<'a> ReadReq<'a> {
        pub fn new(fabric_filtered: bool) -> Self {
            Self {
                fabric_filtered,
                ..Default::default()
            }
        }

        pub fn set_attr_requests(mut self, requests: &'a [AttrPath]) -> Self {
            self.attr_requests = Some(requests);
            self
        }
    }

    impl<'a> ToTLV for ReadReq<'a> {
        fn to_tlv(self: &ReadReq<'a>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            if let Some(attr_requests) = self.attr_requests {
                tw.put_start_array(TagType::Context(ReadReqTag::AttrRequests as u8))?;
                for request in attr_requests {
                    tw.put_object(TagType::Anonymous, request)?;
                }
                tw.put_end_container()?;
            }
            tw.put_bool(
                TagType::Context(ReadReqTag::FabricFiltered as u8),
                self.fabric_filtered,
            )?;
            tw.put_end_container()
        }
    }

    // Report Data
    // TODO: Differs from spec
    pub enum ReportDataTag {
        _SubscriptionId = 0,
        AttributeReports = 1,
        _EventReport = 2,
        _MoreChunkedMsgs = 3,
        SupressResponse = 4,
    }

    // Write Response
    pub enum WriteResponseTag {
        WriteResponses = 0,
    }
}

pub mod ib {
    use std::fmt::{Debug, Formatter};

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
    #[derive(Clone, Copy)]
    pub enum InvResp<'a> {
        Cmd(CmdData<'a>),
        Status(CmdPath, Status),
    }

    #[derive(FromPrimitive)]
    enum InvRespTag {
        Cmd = 0,
        Status = 1,
    }

    enum CmdStatusTag {
        Path = 0,
        Status = 1,
    }

    impl<'a> InvResp<'a> {
        pub fn cmd_new(endpoint: u16, cluster: u32, cmd: u16, data: CmdDataGen<'a>) -> Self {
            Self::Cmd(CmdData::new(
                CmdPath::new(Some(endpoint), Some(cluster), Some(cmd)),
                data,
            ))
        }

        pub fn status_new(cmd_path: CmdPath, status: IMStatusCode, cluster_status: u16) -> Self {
            Self::Status(cmd_path, Status::new(status, cluster_status))
        }

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
                InvRespTag::Cmd => {
                    let cmd_path = resp.find_tag(CmdDataTag::Path as u32)?;
                    let data = resp.find_tag(CmdDataTag::Data as u32)?;
                    Ok(Self::Cmd(CmdData {
                        path: CmdPath::from_tlv(&cmd_path)?,
                        data: CmdDataType::Tlv(data),
                    }))
                }
                InvRespTag::Status => {
                    let cmd_path = resp.find_tag(CmdStatusTag::Path as u32)?;
                    let status = resp.find_tag(CmdStatusTag::Status as u32)?;
                    Ok(Self::Status(
                        CmdPath::from_tlv(&cmd_path)?,
                        Status::from_tlv(&status)?,
                    ))
                }
            }
        }
    }

    impl<'a> ToTLV for InvResp<'a> {
        fn to_tlv(self: &InvResp<'a>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            match self {
                InvResp::Cmd(cmd_data) => {
                    tw.put_object(TagType::Context(InvRespTag::Cmd as u8), cmd_data)?;
                }
                InvResp::Status(cmd_path, status) => {
                    tw.put_start_struct(TagType::Context(InvRespTag::Status as u8))?;
                    tw.put_object(TagType::Context(CmdStatusTag::Path as u8), cmd_path)?;
                    tw.put_object(TagType::Context(CmdStatusTag::Status as u8), status)?;
                }
            }
            tw.put_end_container()?;
            tw.put_end_container()
        }
    }

    type CmdDataGen<'a> = &'a dyn Fn(&mut TLVWriter) -> Result<(), Error>;

    #[derive(Clone, Copy)]
    pub enum CmdDataType<'a> {
        Closure(CmdDataGen<'a>),
        Tlv(TLVElement<'a>),
    }

    impl<'a> Debug for CmdDataType<'a> {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
            match *self {
                Self::Closure(_) => write!(f, "Contains closure"),
                Self::Tlv(t) => write!(f, "{:?}", t),
            }?;
            Ok(())
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct CmdData<'a> {
        pub path: CmdPath,
        pub data: CmdDataType<'a>,
    }

    enum CmdDataTag {
        Path = 0,
        Data = 1,
    }

    impl<'a> CmdData<'a> {
        pub fn new(path: CmdPath, data: CmdDataGen<'a>) -> Self {
            Self {
                path,
                data: CmdDataType::Closure(data),
            }
        }
    }

    impl<'a> ToTLV for CmdData<'a> {
        fn to_tlv(self: &CmdData<'a>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            tw.put_object(TagType::Context(CmdDataTag::Path as u8), &self.path)?;
            // TODO: We are cheating here a little bit. This following 'Data' need
            // not be a 'structure'. Somebody could directly embed u8 at the tag
            // 'CmdDataTag::Data'. We will have to modify this (and all the callers)
            // when we stumble across that scenario
            tw.put_start_struct(TagType::Context(CmdDataTag::Data as u8))?;
            match self.data {
                CmdDataType::Closure(c) => {
                    (c)(tw)?;
                }
                CmdDataType::Tlv(_) => (panic!("Not yet implemented")),
            };
            tw.put_end_container()
        }
    }

    // Status
    #[derive(Debug, Clone, Copy, PartialEq)]
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
    #[derive(Clone, Copy)]
    pub enum AttrResp<'a> {
        Data(AttrData<'a>),
        Status(AttrStatus),
    }

    #[derive(FromPrimitive)]
    enum AttrRespTag {
        Status = 0,
        Data = 1,
    }

    impl<'a> AttrResp<'a> {
        pub fn new(data_ver: u32, path: &AttrPath, data: AttrDataType<'a>) -> Self {
            AttrResp::Data(AttrData::new(Some(data_ver), *path, data))
        }

        pub fn write_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), IMStatusCode> {
            let _ = tw.put_start_struct(tag_type);
            match self {
                AttrResp::Data(data) => {
                    // In this case, we'll have to add the AttributeDataIb
                    // The only possible return here is if the AttrData read returns an error
                    data.write_tlv(tw, TagType::Context(AttrRespTag::Data as u8))?;
                }
                AttrResp::Status(status) => {
                    // In this case, we'll have to add the AttributeStatusIb
                    let _ = tw.put_object(TagType::Context(AttrRespTag::Status as u8), status);
                }
            }
            let _ = tw.put_end_container();
            Ok(())
        }

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
                AttrRespTag::Data => Ok(AttrResp::Data(AttrData::from_tlv(&resp)?)),
                AttrRespTag::Status => Ok(AttrResp::Status(AttrStatus::from_tlv(&resp)?)),
            }
        }
    }

    impl<'a> ToTLV for AttrResp<'a> {
        fn to_tlv(self: &AttrResp<'a>, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            self.write_tlv(tw, tag_type).map_err(|_| Error::Invalid)
        }
    }

    type AttrDataGen<'a> = &'a dyn Fn(TagType, &mut TLVWriter) -> Result<(), IMStatusCode>;

    #[derive(Clone, Copy)]
    pub enum AttrDataType<'a> {
        Closure(AttrDataGen<'a>),
        Tlv(TLVElement<'a>),
    }

    impl<'a> PartialEq for AttrDataType<'a> {
        fn eq(&self, other: &Self) -> bool {
            match *self {
                AttrDataType::Closure(_) => false,
                AttrDataType::Tlv(a) => {
                    if let AttrDataType::Tlv(b) = *other {
                        a == b
                    } else {
                        false
                    }
                }
            }
        }
    }

    impl<'a> Debug for AttrDataType<'a> {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
            match *self {
                AttrDataType::Closure(_) => write!(f, "Contains closure"),
                AttrDataType::Tlv(t) => write!(f, "{:?}", t),
            }?;
            Ok(())
        }
    }

    // Attribute Data
    #[derive(Clone, Copy, PartialEq)]
    pub struct AttrData<'a> {
        pub data_ver: Option<u32>,
        pub path: AttrPath,
        pub data: AttrDataType<'a>,
    }

    pub enum AttrDataTag {
        DataVersion = 0,
        Path = 1,
        Data = 2,
    }

    impl<'a> AttrData<'a> {
        pub fn new(data_ver: Option<u32>, path: AttrPath, data: AttrDataType<'a>) -> Self {
            Self {
                data_ver,
                path,
                data,
            }
        }

        pub fn from_tlv(attr_data: &TLVElement<'a>) -> Result<Self, Error> {
            let data_ver_tag = attr_data.find_tag(AttrDataTag::DataVersion as u32);
            let data_ver = if data_ver_tag.is_ok() {
                error!("Data Version handling not yet supported");
                Some(data_ver_tag?.get_u32()?)
            } else {
                None
            };

            let path = attr_data.find_tag(AttrDataTag::Path as u32)?;
            let path = AttrPath::from_tlv(&path)?;
            let data = attr_data.find_tag(AttrDataTag::Data as u32)?;
            Ok(Self {
                data_ver,
                path,
                data: AttrDataType::Tlv(data),
            })
        }

        fn write_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), IMStatusCode> {
            let _ = tw.put_start_struct(tag_type);
            if let Some(data_ver) = self.data_ver {
                let _ = tw.put_u32(TagType::Context(AttrDataTag::DataVersion as u8), data_ver);
            }
            let _ = tw.put_object(TagType::Context(AttrDataTag::Path as u8), &self.path);
            match self.data {
                AttrDataType::Closure(f) => (f)(TagType::Context(AttrDataTag::Data as u8), tw)?,
                AttrDataType::Tlv(_) => (panic!("Not yet implemented")),
            }
            let _ = tw.put_end_container();
            Ok(())
        }
    }

    impl<'a> ToTLV for AttrData<'a> {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            self.write_tlv(tw, tag_type).map_err(|_| Error::Invalid)
        }
    }

    // Attribute Status
    pub enum AttrStatusTag {
        Path = 0,
        Status = 1,
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
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

        pub fn from_tlv<'a>(resp: &TLVElement<'a>) -> Result<Self, Error> {
            let resp = resp.confirm_struct()?;
            let path = resp.find_tag(AttrStatusTag::Path as u32)?;
            let path = AttrPath::from_tlv(&path)?;
            let status = resp.find_tag(AttrStatusTag::Status as u32)?;
            let status = Status::from_tlv(&status)?;
            Ok(Self { path, status })
        }
    }

    impl ToTLV for AttrStatus {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            tw.put_start_struct(tag_type)?;
            // Attribute Status IB
            tw.put_object(TagType::Context(AttrStatusTag::Path as u8), &self.path)?;
            // Status IB
            tw.put_object(TagType::Context(AttrStatusTag::Status as u8), &self.status)?;
            tw.put_end_container()
        }
    }

    // Attribute Path
    #[derive(Default, Clone, Copy, Debug, PartialEq)]
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
    macro_rules! cmd_path_ib {
        ($endpoint:literal,$cluster:ident,$command:expr) => {{
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
}
