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
        !matches!(
            *self,
            GenericPath {
                endpoint: Some(_),
                cluster: Some(_),
                leaf: Some(_),
            }
        )
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
    use std::fmt::Debug;

    use crate::{
        data_model::objects::{AttrDetails, EncodeValue},
        error::Error,
        interaction_model::core::IMStatusCode,
        tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
    };
    use log::error;

    use super::GenericPath;

    // Command Response
    #[derive(Clone, Copy, FromTLV, ToTLV)]
    #[tlvargs(lifetime = "'a")]
    pub enum InvResp<'a> {
        Cmd(CmdData<'a>),
        Status(CmdStatus),
    }

    impl<'a> InvResp<'a> {
        pub fn cmd_new(endpoint: u16, cluster: u32, cmd: u16, data: EncodeValue<'a>) -> Self {
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

    #[derive(Debug, Clone, Copy, FromTLV, ToTLV)]
    #[tlvargs(lifetime = "'a")]
    pub struct CmdData<'a> {
        pub path: CmdPath,
        pub data: EncodeValue<'a>,
    }

    impl<'a> CmdData<'a> {
        pub fn new(path: CmdPath, data: EncodeValue<'a>) -> Self {
            Self { path, data }
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
    #[derive(Clone, Copy, FromTLV, ToTLV)]
    #[tlvargs(lifetime = "'a")]
    pub enum AttrResp<'a> {
        Status(AttrStatus),
        Data(AttrData<'a>),
    }

    impl<'a> AttrResp<'a> {
        pub fn new(data_ver: u32, path: &AttrPath, data: EncodeValue<'a>) -> Self {
            AttrResp::Data(AttrData::new(Some(data_ver), *path, data))
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

    #[derive(Debug)]
    /// Operations on an Interaction Model List
    pub enum ListOperation {
        /// Add (append) an item to the list
        AddItem,
        /// Edit an item from the list
        EditItem(u16),
        /// Delete item from the list
        DeleteItem(u16),
        /// Delete the whole list
        DeleteList,
    }

    /// Attribute Lists in Attribute Data are special. Infer the correct meaning using this function
    pub fn attr_list_op<F>(
        attr: AttrDetails,
        data: &TLVElement,
        mut f: F,
    ) -> Result<(), IMStatusCode>
    where
        F: FnMut(ListOperation, &TLVElement) -> Result<(), IMStatusCode>,
    {
        if let Some(index) = attr.list_index {
            // If list index is valid,
            //    - this is a modify item or delete item operation
            if data.null().is_ok() {
                // If data is NULL, delete item
                f(ListOperation::DeleteItem(index), data)
            } else {
                f(ListOperation::EditItem(index), data)
            }
        } else {
            if data.confirm_array().is_ok() {
                // If data is list, this is either Delete List or OverWrite List operation
                // in either case, we have to first delete the whole list
                f(ListOperation::DeleteList, data)?;
                // Now the data must be a list, that should be added item by item

                let container = data.iter().ok_or(Error::Invalid)?;
                for d in container {
                    f(ListOperation::AddItem, &d)?;
                }
                Ok(())
            } else {
                // If data is not a list, this must be an add operation
                f(ListOperation::AddItem, data)
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
