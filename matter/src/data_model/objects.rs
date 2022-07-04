use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode, messages::GenericPath},
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
};
use bitflags::bitflags;
use log::error;
use num_derive::FromPrimitive;
use rand::Rng;
use std::fmt::{self, Debug, Formatter};

bitflags! {
    #[derive(Default)]
    pub struct Access: u16 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const FAB_SCOPED = 0x0004;
        const FAB_SENSITIVE = 0x0008;
        const NEED_VIEW = 0x0010;
        const NEED_OPERATE = 0x0020;
        const NEED_MANAGE = 0x0040;
        const NEED_ADMIN = 0x0080;
        const TIMED_ONLY = 0x0100;
        const RV = Self::READ.bits | Self::NEED_VIEW.bits;
        const RWVA = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_ADMIN.bits;
        const RWFA = Self::READ.bits | Self::WRITE.bits | Self::FAB_SCOPED.bits | Self::NEED_ADMIN.bits;
        const RWVM = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Quality: u8 {
        const NONE = 0x00;
        const SCENE = 0x01;
        const PERSISTENT = 0x02;
        const FIXED = 0x03;
        const NULLABLE = 0x04;
    }
}

/* This file needs some major revamp.
 * - instead of allocating all over the heap, we should use some kind of slab/block allocator
 * - instead of arrays, can use linked-lists to conserve space and avoid the internal fragmentation
 */
pub const ENDPTS_PER_ACC: usize = 3;
pub const CLUSTERS_PER_ENDPT: usize = 7;
pub const ATTRS_PER_CLUSTER: usize = 8;
pub const CMDS_PER_CLUSTER: usize = 8;

#[derive(PartialEq, Copy, Clone)]
pub enum AttrValue {
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Bool(bool),
    Custom,
}

impl Debug for AttrValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            AttrValue::Int64(v) => write!(f, "{:?}", *v),
            AttrValue::Uint8(v) => write!(f, "{:?}", *v),
            AttrValue::Uint16(v) => write!(f, "{:?}", *v),
            AttrValue::Uint32(v) => write!(f, "{:?}", *v),
            AttrValue::Uint64(v) => write!(f, "{:?}", *v),
            AttrValue::Bool(v) => write!(f, "{:?}", *v),
            AttrValue::Custom => write!(f, "custom-attribute"),
        }?;
        Ok(())
    }
}

impl ToTLV for AttrValue {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        // What is the time complexity of such long match statements?
        match self {
            AttrValue::Bool(v) => tw.bool(tag_type, *v),
            AttrValue::Uint8(v) => tw.u8(tag_type, *v),
            AttrValue::Uint16(v) => tw.u16(tag_type, *v),
            AttrValue::Uint32(v) => tw.u32(tag_type, *v),
            AttrValue::Uint64(v) => tw.u64(tag_type, *v),
            _ => {
                error!("Attribute type not yet supported");
                Err(Error::AttributeNotFound)
            }
        }
    }
}

impl AttrValue {
    fn update_from_tlv(&mut self, tr: &TLVElement) -> Result<(), Error> {
        match self {
            AttrValue::Bool(v) => *v = tr.bool()?,
            AttrValue::Uint8(v) => *v = tr.u8()?,
            AttrValue::Uint16(v) => *v = tr.u16()?,
            AttrValue::Uint32(v) => *v = tr.u32()?,
            AttrValue::Uint64(v) => *v = tr.u64()?,
            _ => {
                error!("Attribute type not yet supported");
                return Err(Error::AttributeNotFound);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Attribute {
    id: u16,
    value: AttrValue,
    quality: Quality,
    access: Access,
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute {
            id: 0,
            value: AttrValue::Bool(true),
            quality: Default::default(),
            access: Default::default(),
        }
    }
}

impl Attribute {
    pub fn new(
        id: u16,
        value: AttrValue,
        access: Access,
        quality: Quality,
    ) -> Result<Attribute, Error> {
        Ok(Attribute {
            id,
            value,
            access,
            quality,
        })
    }

    pub fn set_value(&mut self, value: AttrValue) -> Result<(), Error> {
        if !self.quality.contains(Quality::FIXED) {
            self.value = value;
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn is_system_attr(attr_id: u16) -> bool {
        attr_id >= (GlobalElements::ServerGenCmd as u16)
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.id, self.value)
    }
}

#[derive(FromPrimitive, Debug)]
pub enum GlobalElements {
    _ClusterRevision = 0xFFFD,
    FeatureMap = 0xFFFC,
    AttributeList = 0xFFFB,
    _EventList = 0xFFFA,
    _ClientGenCmd = 0xFFF9,
    ServerGenCmd = 0xFFF8,
    _FabricIndex = 0xFE,
}

pub trait ClusterType {
    fn base(&self) -> &Cluster;
    fn base_mut(&mut self) -> &mut Cluster;
    fn read_custom_attribute(
        &self,
        _tag: TagType,
        _tw: &mut TLVWriter,
        _attr_id: u16,
    ) -> Result<(), IMStatusCode> {
        Err(IMStatusCode::UnsupportedAttribute)
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);

        Err(IMStatusCode::UnsupportedCommand)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base_mut().write_attribute(data, attr_id)
    }
}

pub struct Cluster {
    id: u32,
    attributes: Vec<Attribute>,
    feature_map: Option<u32>,
    data_ver: u32,
}

impl Cluster {
    pub fn new(id: u32) -> Result<Cluster, Error> {
        let mut c = Cluster {
            id,
            attributes: Vec::with_capacity(ATTRS_PER_CLUSTER),
            feature_map: None,
            data_ver: rand::thread_rng().gen_range(0..0xFFFFFFFF),
        };
        c.add_default_attributes()?;
        Ok(c)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn get_dataver(&self) -> u32 {
        self.data_ver
    }

    pub fn set_feature_map(&mut self, map: u32) -> Result<(), Error> {
        if self.feature_map.is_none() {
            self.add_attribute(Attribute::new(
                GlobalElements::FeatureMap as u16,
                AttrValue::Uint32(map),
                Access::RV,
                Quality::NONE,
            )?)?;
        } else {
            self.write_attribute_raw(GlobalElements::FeatureMap as u16, AttrValue::Uint32(map))
                .map_err(|_| Error::Invalid)?;
        }
        self.feature_map = Some(map);
        Ok(())
    }

    fn add_default_attributes(&mut self) -> Result<(), Error> {
        self.add_attribute(Attribute::new(
            GlobalElements::AttributeList as u16,
            AttrValue::Custom,
            Access::RV,
            Quality::NONE,
        )?)
    }

    pub fn add_attribute(&mut self, attr: Attribute) -> Result<(), Error> {
        if self.attributes.len() < self.attributes.capacity() {
            self.attributes.push(attr);
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    fn get_attribute_index(&self, attr_id: u16) -> Option<usize> {
        self.attributes.iter().position(|c| c.id == attr_id)
    }

    fn get_attribute(&self, attr_id: u16) -> Result<&Attribute, Error> {
        let index = self
            .get_attribute_index(attr_id)
            .ok_or(Error::AttributeNotFound)?;
        Ok(&self.attributes[index])
    }

    fn get_attribute_mut(&mut self, attr_id: u16) -> Result<&mut Attribute, Error> {
        let index = self
            .get_attribute_index(attr_id)
            .ok_or(Error::AttributeNotFound)?;
        Ok(&mut self.attributes[index])
    }

    // Returns a slice of attribute, with either a single attribute or all (wildcard)
    pub fn get_wildcard_attribute(&self, attribute: Option<u16>) -> &[Attribute] {
        if let Some(a) = attribute {
            if let Some(i) = self.get_attribute_index(a) {
                &self.attributes[i..i + 1]
            } else {
                // empty slice
                &[] as &[Attribute]
            }
        } else {
            &self.attributes[..]
        }
    }

    pub fn read_attribute(
        c: &dyn ClusterType,
        tag: TagType,
        tw: &mut TLVWriter,
        attr_id: u16,
    ) -> Result<(), IMStatusCode> {
        let base = c.base();
        let a = base
            .get_attribute(attr_id)
            .map_err(|_| IMStatusCode::UnsupportedAttribute)?;
        if !a.access.contains(Access::READ) {
            return Err(IMStatusCode::UnsupportedRead);
        }

        if a.value != AttrValue::Custom || Attribute::is_system_attr(attr_id) {
            base.read_standard_attribute(tag, tw, a)
        } else {
            c.read_custom_attribute(tag, tw, attr_id)
        }
    }

    fn read_standard_attribute(
        &self,
        tag: TagType,
        tw: &mut TLVWriter,
        attr: &Attribute,
    ) -> Result<(), IMStatusCode> {
        let global_attr: Option<GlobalElements> = num::FromPrimitive::from_u16(attr.id);
        if let Some(global_attr) = global_attr {
            match global_attr {
                GlobalElements::AttributeList => {
                    let _ = tw.start_array(tag);
                    for a in &self.attributes {
                        let _ = tw.u16(TagType::Anonymous, a.id);
                    }
                    let _ = tw.end_container();
                    Ok(())
                }
                GlobalElements::FeatureMap => {
                    let val = if let Some(m) = self.feature_map { m } else { 0 };
                    let _ = tw.u32(tag, val);
                    Ok(())
                }
                _ => {
                    error!("This attribute not yet handled {:?}", global_attr);
                    Err(IMStatusCode::UnsupportedAttribute)
                }
            }
        } else {
            let _ = attr.value.to_tlv(tw, tag);
            Ok(())
        }
    }

    pub fn read_attribute_raw(&self, attr_id: u16) -> Result<&AttrValue, IMStatusCode> {
        let a = self
            .get_attribute(attr_id)
            .map_err(|_| IMStatusCode::UnsupportedAttribute)?;
        Ok(&a.value)
    }

    pub fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        let a = self
            .get_attribute_mut(attr_id)
            .map_err(|_| IMStatusCode::UnsupportedAttribute)?;
        if !a.access.contains(Access::WRITE) {
            return Err(IMStatusCode::UnsupportedWrite);
        }
        if a.value != AttrValue::Custom {
            let mut value = a.value;
            value
                .update_from_tlv(data)
                .map_err(|_| IMStatusCode::Failure)?;
            a.set_value(value)
                .map_err(|_| IMStatusCode::UnsupportedWrite)
        } else {
            Err(IMStatusCode::UnsupportedAttribute)
        }
    }

    pub fn write_attribute_raw(&mut self, attr_id: u16, value: AttrValue) -> Result<(), Error> {
        let a = self.get_attribute_mut(attr_id)?;
        a.set_value(value)
    }
}

impl std::fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}, ", self.id)?;
        write!(f, "attrs[")?;
        let mut comma = "";
        for element in self.attributes.iter() {
            write!(f, "{} {}", comma, element)?;
            comma = ",";
        }
        write!(f, " ], ")
    }
}

pub struct Endpoint {
    clusters: Vec<Box<dyn ClusterType>>,
}

impl Endpoint {
    pub fn new() -> Result<Box<Endpoint>, Error> {
        Ok(Box::new(Endpoint {
            clusters: Vec::with_capacity(CLUSTERS_PER_ENDPT),
        }))
    }

    pub fn add_cluster(&mut self, cluster: Box<dyn ClusterType>) -> Result<(), Error> {
        if self.clusters.len() < self.clusters.capacity() {
            self.clusters.push(cluster);
            Ok(())
        } else {
            Err(Error::NoSpace)
        }
    }

    fn get_cluster_index(&self, cluster_id: u32) -> Option<usize> {
        self.clusters.iter().position(|c| c.base().id == cluster_id)
    }

    pub fn get_cluster(&self, cluster_id: u32) -> Result<&dyn ClusterType, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_ref())
    }

    pub fn get_cluster_mut(&mut self, cluster_id: u32) -> Result<&mut dyn ClusterType, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_mut())
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters(&self, cluster: Option<u32>) -> &[Box<dyn ClusterType>] {
        if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                &self.clusters[i..i + 1]
            } else {
                // empty slice
                &[] as &[Box<dyn ClusterType>]
            }
        } else {
            self.clusters.as_slice()
        }
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters_mut(
        &mut self,
        cluster: Option<u32>,
    ) -> &mut [Box<dyn ClusterType>] {
        if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                &mut self.clusters[i..i + 1]
            } else {
                // empty slice
                &mut [] as &mut [Box<dyn ClusterType>]
            }
        } else {
            &mut self.clusters[..]
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clusters:[")?;
        let mut comma = "";
        for element in self.clusters.iter() {
            write!(f, "{} {{ {} }}", comma, element.base())?;
            comma = ", ";
        }
        write!(f, "]")
    }
}

pub trait ChangeConsumer {
    fn endpoint_added(&self, id: u16, endpoint: &mut Endpoint) -> Result<(), Error>;
}

#[derive(Default)]
pub struct Node {
    endpoints: [Option<Box<Endpoint>>; ENDPTS_PER_ACC],
    changes_cb: Option<Box<dyn ChangeConsumer>>,
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (i, element) in self.endpoints.iter().enumerate() {
            if let Some(e) = element {
                writeln!(f, "endpoint {}: {}", i, e)?;
            }
        }
        write!(f, "")
    }
}

impl Node {
    pub fn new() -> Result<Box<Node>, Error> {
        let node = Box::new(Node::default());
        Ok(node)
    }

    pub fn set_changes_cb(&mut self, consumer: Box<dyn ChangeConsumer>) {
        self.changes_cb = Some(consumer);
    }

    pub fn add_endpoint(&mut self) -> Result<u32, Error> {
        let index = self
            .endpoints
            .iter()
            .position(|x| x.is_none())
            .ok_or(Error::NoSpace)?;
        let mut endpoint = Endpoint::new()?;
        if let Some(cb) = &self.changes_cb {
            cb.endpoint_added(index as u16, &mut endpoint)?;
        }
        self.endpoints[index] = Some(endpoint);
        Ok(index as u32)
    }

    pub fn get_endpoint(&self, endpoint_id: u16) -> Result<&Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_ref()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_endpoint_mut(&mut self, endpoint_id: u16) -> Result<&mut Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_mut()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_cluster_mut(&mut self, e: u16, c: u32) -> Result<&mut dyn ClusterType, Error> {
        self.get_endpoint_mut(e)?.get_cluster_mut(c)
    }

    pub fn get_cluster(&self, e: u16, c: u32) -> Result<&dyn ClusterType, Error> {
        self.get_endpoint(e)?.get_cluster(c)
    }

    pub fn add_cluster(
        &mut self,
        endpoint_id: u32,
        cluster: Box<dyn ClusterType>,
    ) -> Result<(), Error> {
        let endpoint_id = endpoint_id as usize;
        if endpoint_id < ENDPTS_PER_ACC {
            self.endpoints[endpoint_id]
                .as_mut()
                .ok_or(Error::NoEndpoint)?
                .add_cluster(cluster)
        } else {
            Err(Error::Invalid)
        }
    }

    // Returns a slice of endpoints, with either a single endpoint or all (wildcard)
    pub fn get_wildcard_endpoints(
        &self,
        endpoint: Option<u16>,
    ) -> (&[Option<Box<Endpoint>>], usize) {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                // empty slice
                (&[] as &[Option<Box<Endpoint>>], 0_usize)
            } else {
                (&self.endpoints[e..e + 1], e)
            }
        } else {
            (&self.endpoints[..], 0)
        }
    }

    pub fn get_wildcard_endpoints_mut(
        &mut self,
        endpoint: Option<u16>,
    ) -> (&mut [Option<Box<Endpoint>>], usize) {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                // empty slice
                (&mut [] as &mut [Option<Box<Endpoint>>], 0_usize)
            } else {
                (&mut self.endpoints[e..e + 1], e)
            }
        } else {
            (&mut self.endpoints[..], 0)
        }
    }

    pub fn for_each_endpoint<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &Endpoint),
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints(path.endpoint);
        for e in endpoints.iter() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_ref());
            }
            endpoint_id += 1;
        }
    }

    pub fn for_each_endpoint_mut<T>(&mut self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &mut Endpoint),
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints_mut(path.endpoint);
        for e in endpoints.iter_mut() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_mut());
            }
            endpoint_id += 1;
        }
    }

    pub fn for_each_cluster<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &dyn ClusterType),
    {
        self.for_each_endpoint(path, |p, e| {
            let mut current_path = *p;
            let clusters = e.get_wildcard_clusters(p.cluster);
            for c in clusters.iter() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_ref());
            }
        });
    }

    pub fn for_each_cluster_mut<T>(&mut self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &mut dyn ClusterType),
    {
        self.for_each_endpoint_mut(path, |p, e| {
            let mut current_path = *p;
            let clusters = e.get_wildcard_clusters_mut(p.cluster);

            for c in clusters.iter_mut() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_mut());
            }
        });
    }

    pub fn for_each_attribute<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &dyn ClusterType),
    {
        self.for_each_cluster(path, |current_path, c| {
            let mut current_path = *current_path;
            let attributes = c
                .base()
                .get_wildcard_attribute(path.leaf.map(|at| at as u16));
            for a in attributes.iter() {
                current_path.leaf = Some(a.id as u32);
                f(&current_path, c);
            }
        });
    }
}
