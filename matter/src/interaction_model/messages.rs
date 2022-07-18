use crate::{
    error::Error,
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
};

// A generic path with endpoint, clusters, and a leaf
// The leaf could be command, attribute, event
#[derive(Default, Clone, Copy, Debug, PartialEq, FromTLV, ToTLV)]
#[tlvargs(datatype = "list")]
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
        tlv::{FromTLV, TLVArray, TLVElement, TLVWriter, TagType, ToTLV},
    };

    use super::ib::{AttrData, AttrPath};

    pub enum InvRespTag {
        SupressResponse = 0,
        InvokeResponses = 1,
    }

    pub enum InvReqTag {
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

    #[derive(Default, ToTLV, FromTLV)]
    #[tlvargs(lifetime = "'a")]
    pub struct ReadReq<'a> {
        pub attr_requests: Option<TLVArray<'a, AttrPath>>,
        event_requests: Option<bool>,
        event_filters: Option<bool>,
        pub fabric_filtered: bool,
        pub dataver_filters: Option<TLVArray<'a, bool>>,
    }

    impl<'a> ReadReq<'a> {
        pub fn new(fabric_filtered: bool) -> Self {
            Self {
                fabric_filtered,
                ..Default::default()
            }
        }

        pub fn set_attr_requests(mut self, requests: &'a [AttrPath]) -> Self {
            self.attr_requests = Some(TLVArray::new(requests));
            self
        }
    }

    pub enum WriteReqTag {
        SuppressResponse = 0,
        _TimedRequest = 1,
        WriteRequests = 2,
        _MoreChunkedMsgs = 3,
    }

    #[derive(ToTLV, FromTLV)]
    #[tlvargs(lifetime = "'b")]
    pub struct WriteReq<'a, 'b> {
        pub supress_response: Option<bool>,
        timed_request: Option<bool>,
        pub write_requests: TLVArray<'a, AttrData<'b>>,
        more_chunked: Option<bool>,
    }

    impl<'a, 'b> WriteReq<'a, 'b> {
        pub fn new(supress_response: bool, write_requests: &'a [AttrData<'b>]) -> Self {
            let mut w = Self {
                supress_response: None,
                write_requests: TLVArray::new(write_requests),
                timed_request: None,
                more_chunked: None,
            };
            if supress_response {
                w.supress_response = Some(true);
            }
            w
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
    pub enum WriteRespTag {
        WriteResponses = 0,
    }
}

pub mod ib {
    use std::fmt::{Debug, Formatter};

    use crate::{
        data_model::objects::EncodeValue,
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
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
            tw.start_struct(tag_type)?;
            match self {
                InvResp::Cmd(cmd_data) => {
                    cmd_data.to_tlv(tw, TagType::Context(InvRespTag::Cmd as u8))?;
                }
                InvResp::Status(cmd_path, status) => {
                    tw.start_struct(TagType::Context(InvRespTag::Status as u8))?;
                    cmd_path.to_tlv(tw, TagType::Context(CmdStatusTag::Path as u8))?;
                    status.to_tlv(tw, TagType::Context(CmdStatusTag::Status as u8))?;
                }
            }
            tw.end_container()?;
            tw.end_container()
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
            tw.start_struct(tag_type)?;
            self.path
                .to_tlv(tw, TagType::Context(CmdDataTag::Path as u8))?;
            // TODO: We are cheating here a little bit. This following 'Data' need
            // not be a 'structure'. Somebody could directly embed u8 at the tag
            // 'CmdDataTag::Data'. We will have to modify this (and all the callers)
            // when we stumble across that scenario
            tw.start_struct(TagType::Context(CmdDataTag::Data as u8))?;
            match self.data {
                CmdDataType::Closure(c) => {
                    (c)(tw)?;
                }
                CmdDataType::Tlv(_) => (panic!("Not yet implemented")),
            };
            tw.end_container()
        }
    }

    // Status
    #[derive(Debug, Clone, Copy, PartialEq, FromTLV, ToTLV)]
    pub struct Status {
        pub status: IMStatusCode,
        pub cluster_status: u16,
    }

    impl Status {
        pub fn new(status: IMStatusCode, cluster_status: u16) -> Status {
            Status {
                status,
                cluster_status,
            }
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
        pub fn new(data_ver: u32, path: &AttrPath, data: EncodeValue<'a>) -> Self {
            AttrResp::Data(AttrData::new(Some(data_ver), *path, data))
        }

        pub fn write_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), IMStatusCode> {
            let _ = tw.start_struct(tag_type);
            match self {
                AttrResp::Data(data) => {
                    // In this case, we'll have to add the AttributeDataIb
                    // The only possible return here is if the AttrData read returns an error
                    data.write_tlv(tw, TagType::Context(AttrRespTag::Data as u8))?;
                }
                AttrResp::Status(status) => {
                    // In this case, we'll have to add the AttributeStatusIb
                    let _ = status.to_tlv(tw, TagType::Context(AttrRespTag::Status as u8));
                }
            }
            let _ = tw.end_container();
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

    // Attribute Data
    #[derive(Clone, Copy, PartialEq)]
    pub struct AttrData<'a> {
        pub data_ver: Option<u32>,
        pub path: AttrPath,
        pub data: EncodeValue<'a>,
    }

    pub enum AttrDataTag {
        DataVersion = 0,
        Path = 1,
        Data = 2,
    }

    impl<'a> AttrData<'a> {
        pub fn new(data_ver: Option<u32>, path: AttrPath, data: EncodeValue<'a>) -> Self {
            Self {
                data_ver,
                path,
                data,
            }
        }

        fn write_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), IMStatusCode> {
            let _ = tw.start_struct(tag_type);
            if let Some(data_ver) = self.data_ver {
                let _ = tw.u32(TagType::Context(AttrDataTag::DataVersion as u8), data_ver);
            }
            let _ = self
                .path
                .to_tlv(tw, TagType::Context(AttrDataTag::Path as u8));
            match self.data {
                EncodeValue::Closure(f) => (f)(TagType::Context(AttrDataTag::Data as u8), tw)?,
                EncodeValue::Tlv(_) => (panic!("Not yet implemented")),
                EncodeValue::Value(v) => v.to_tlv(tw, TagType::Context(AttrDataTag::Data as u8))?,
            }
            let _ = tw.end_container();
            Ok(())
        }
    }

    impl<'a> FromTLV<'a> for AttrData<'a> {
        fn from_tlv(attr_data: &TLVElement<'a>) -> Result<Self, Error> {
            let data_ver_tag = attr_data.find_tag(AttrDataTag::DataVersion as u32);
            let data_ver = if data_ver_tag.is_ok() {
                error!("Data Version handling not yet supported");
                Some(data_ver_tag?.u32()?)
            } else {
                None
            };

            let path = attr_data.find_tag(AttrDataTag::Path as u32)?;
            let path = AttrPath::from_tlv(&path)?;
            let data = attr_data.find_tag(AttrDataTag::Data as u32)?;
            Ok(Self {
                data_ver,
                path,
                data: EncodeValue::Tlv(data),
            })
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

    #[derive(Debug, Clone, Copy, PartialEq, FromTLV, ToTLV)]
    pub struct AttrStatus {
        path: AttrPath,
        status: Status,
    }

    impl AttrStatus {
        pub fn new(path: &GenericPath, status: IMStatusCode, cluster_status: u16) -> Self {
            Self {
                path: AttrPath::new(path),
                status: super::ib::Status::new(status, cluster_status),
            }
        }
    }

    // Attribute Path
    #[derive(Default, Clone, Copy, Debug, PartialEq, FromTLV, ToTLV)]
    #[tlvargs(datatype = "list")]
    pub struct AttrPath {
        pub tag_compression: Option<bool>,
        pub node: Option<u64>,
        pub endpoint: Option<u16>,
        pub cluster: Option<u32>,
        pub attr: Option<u16>,
        pub list_index: Option<u16>,
    }

    impl AttrPath {
        pub fn new(path: &GenericPath) -> Self {
            Self {
                endpoint: path.endpoint,
                cluster: path.cluster,
                attr: path.leaf.map(|x| x as u16),
                ..Default::default()
            }
        }

        pub fn to_gp(&self) -> GenericPath {
            GenericPath::new(self.endpoint, self.cluster, self.attr.map(|x| x as u32))
        }
    }

    // Command Path
    #[derive(Default, Debug, Copy, Clone, PartialEq)]
    pub struct CmdPath {
        pub path: GenericPath,
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
    }

    impl FromTLV<'_> for CmdPath {
        fn from_tlv(cmd_path: &TLVElement) -> Result<Self, Error> {
            let c = CmdPath {
                path: GenericPath::from_tlv(cmd_path)?,
            };

            if c.path.leaf.is_none() {
                error!("Wildcard command parameter not supported");
                Err(Error::CommandNotFound)
            } else {
                Ok(c)
            }
        }
    }

    impl ToTLV for CmdPath {
        fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
            self.path.to_tlv(tw, tag_type)
        }
    }
}
