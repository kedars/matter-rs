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
    /// Returns true, if the path is wildcard
    pub fn is_wildcard(&self) -> bool {
        match *self {
            GenericPath {
                endpoint: Some(_),
                cluster: Some(_),
                leaf: Some(_),
            } => false,
            _ => true,
        }
    }
}

pub mod msg {

    use crate::{
        error::Error,
        tlv::{FromTLV, TLVArray, TLVElement, TLVWriter, TagType, ToTLV},
    };

    use super::ib::{AttrData, AttrPath, CmdData};

    #[derive(FromTLV)]
    #[tlvargs(lifetime = "'a")]
    pub struct InvReq<'a> {
        pub suppress_response: Option<bool>,
        pub timed_request: Option<bool>,
        pub inv_requests: Option<TLVArray<'a, CmdData<'a>>>,
    }

    pub enum InvRespTag {
        SupressResponse = 0,
        InvokeResponses = 1,
    }

    pub enum InvReqTag {
        SupressResponse = 0,
        TimedReq = 1,
        InvokeRequests = 2,
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
        Status(CmdStatus),
    }

    #[derive(FromPrimitive)]
    enum InvRespTag {
        Cmd = 0,
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
            Self::Status(CmdStatus {
                path: cmd_path,
                status: Status::new(status, cluster_status),
            })
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
                InvRespTag::Cmd => Ok(Self::Cmd(CmdData::from_tlv(&resp)?)),
                InvRespTag::Status => Ok(Self::Status(CmdStatus::from_tlv(&resp)?)),
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
                InvResp::Status(cmd_status) => {
                    cmd_status.to_tlv(tw, TagType::Context(InvRespTag::Status as u8))?;
                }
            }
            tw.end_container()
        }
    }

    #[derive(FromTLV, ToTLV, Copy, Clone, PartialEq, Debug)]
    pub struct CmdStatus {
        path: CmdPath,
        status: Status,
    }

    impl CmdStatus {
        pub fn new(path: CmdPath, status: IMStatusCode, cluster_status: u16) -> Self {
            Self {
                path,
                status: Status {
                    status,
                    cluster_status,
                },
            }
        }
    }

    type CmdDataGen<'a> = &'a dyn Fn(&mut TLVWriter) -> Result<(), Error>;

    #[derive(Clone, Copy)]
    pub enum CmdDataType<'a> {
        Closure(CmdDataGen<'a>),
        Tlv(TLVElement<'a>),
    }

    impl<'a> CmdDataType<'a> {
        pub fn get_tlv_ref(&self) -> Option<&TLVElement<'a>> {
            match self {
                CmdDataType::Closure(_) => None,
                CmdDataType::Tlv(t) => Some(&t),
            }
        }
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

    impl<'a> FromTLV<'a> for CmdDataType<'a> {
        fn from_tlv(t: &TLVElement<'a>) -> Result<Self, Error>
        where
            Self: Sized,
        {
            Ok(Self::Tlv(*t))
        }
    }

    impl<'a> ToTLV for CmdDataType<'a> {
        fn to_tlv(
            self: &CmdDataType<'a>,
            tw: &mut TLVWriter,
            tag_type: TagType,
        ) -> Result<(), Error> {
            // TODO: We are cheating here a little bit. This following 'Data' need
            // not be a 'structure'. Somebody could directly embed u8 at the tag
            // 'CmdDataTag::Data'. We will have to modify this (and all the callers)
            // when we stumble across that scenario
            tw.start_struct(tag_type)?;
            match self {
                CmdDataType::Closure(c) => {
                    (c)(tw)?;
                }
                CmdDataType::Tlv(_) => (panic!("Not yet implemented")),
            };
            tw.end_container()
        }
    }

    #[derive(Debug, Clone, Copy, FromTLV, ToTLV)]
    #[tlvargs(lifetime = "'a")]
    pub struct CmdData<'a> {
        pub path: CmdPath,
        pub data: CmdDataType<'a>,
    }

    impl<'a> CmdData<'a> {
        pub fn new(path: CmdPath, data: CmdDataGen<'a>) -> Self {
            Self {
                path,
                data: CmdDataType::Closure(data),
            }
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
                    data.to_tlv(tw, TagType::Context(AttrRespTag::Data as u8))?;
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
    #[derive(Clone, Copy, PartialEq, FromTLV, ToTLV)]
    #[tlvargs(lifetime = "'a")]
    pub struct AttrData<'a> {
        pub data_ver: Option<u32>,
        pub path: AttrPath,
        pub data: EncodeValue<'a>,
    }

    impl<'a> AttrData<'a> {
        pub fn new(data_ver: Option<u32>, path: AttrPath, data: EncodeValue<'a>) -> Self {
            Self {
                data_ver,
                path,
                data,
            }
        }
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
