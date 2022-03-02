use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode, messages::GenericPath},
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::{TLVWriter, ToTLV},
};
use log::error;
use std::fmt::{self, Debug, Formatter};

/* This file needs some major revamp.
 * - instead of allocating all over the heap, we should use some kind of slab/block allocator
 * - instead of arrays, can use linked-lists to conserve space and avoid the internal fragmentation
 */
pub const ENDPTS_PER_ACC: usize = 3;
pub const CLUSTERS_PER_ENDPT: usize = 5;
pub const ATTRS_PER_CLUSTER: usize = 4;
pub const CMDS_PER_CLUSTER: usize = 8;

#[derive(PartialEq)]
pub enum AttrValue {
    Int8(i8),
    Int64(i64),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Bool(bool),
    Custom,
}

impl Debug for AttrValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            AttrValue::Int8(v) => write!(f, "{:?}", *v),
            AttrValue::Int64(v) => write!(f, "{:?}", *v),
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
            AttrValue::Bool(v) => tw.put_bool(tag_type, *v),
            AttrValue::Int8(v) => tw.put_i8(tag_type, *v),
            AttrValue::Uint16(v) => tw.put_u16(tag_type, *v),
            AttrValue::Uint32(v) => tw.put_u32(tag_type, *v),
            AttrValue::Uint64(v) => tw.put_u64(tag_type, *v),
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
            AttrValue::Bool(v) => *v = tr.get_bool()?,
            AttrValue::Int8(v) => *v = tr.get_i8()?,
            AttrValue::Uint16(v) => *v = tr.get_u16()?,
            AttrValue::Uint32(v) => *v = tr.get_u32()?,
            AttrValue::Uint64(v) => *v = tr.get_u64()?,
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
    pub id: u16,
    pub value: AttrValue,
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute {
            id: 0,
            value: AttrValue::Bool(true),
        }
    }
}

impl Attribute {
    pub fn new(id: u16, val: AttrValue) -> Result<Box<Attribute>, Error> {
        let mut a = Box::new(Attribute::default());
        a.id = id;
        a.value = val;
        Ok(a)
    }

    pub fn value_mut(&mut self) -> &mut AttrValue {
        &mut self.value
    }

    pub fn value(&self) -> &AttrValue {
        &self.value
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.id, self.value)
    }
}

pub trait ClusterType {
    fn base(&self) -> &Cluster;
    fn base_mut(&mut self) -> &mut Cluster;
    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error>;
    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode>;
    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode>;
}

pub struct Cluster {
    id: u32,
    attributes: Vec<Box<Attribute>>,
}

impl Cluster {
    pub fn new(id: u32) -> Cluster {
        Cluster {
            id,
            attributes: Vec::with_capacity(ATTRS_PER_CLUSTER),
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn add_attribute(&mut self, attr: Box<Attribute>) -> Result<(), Error> {
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
        Ok(self.attributes[index].as_ref())
    }

    fn get_attribute_mut(&mut self, attr_id: u16) -> Result<&mut Attribute, Error> {
        let index = self
            .get_attribute_index(attr_id)
            .ok_or(Error::AttributeNotFound)?;
        Ok(self.attributes[index].as_mut())
    }

    // Returns a slice of attribute, with either a single attribute or all (wildcard)
    pub fn get_wildcard_attribute(
        &self,
        attribute: Option<u16>,
    ) -> Result<&[Box<Attribute>], IMStatusCode> {
        let attributes = if let Some(a) = attribute {
            if let Some(i) = self.get_attribute_index(a) {
                &self.attributes[i..i + 1]
            } else {
                return Err(IMStatusCode::UnsupportedAttribute);
            }
        } else {
            &self.attributes[..]
        };
        Ok(attributes)
    }

    pub fn read_attribute(
        &self,
        tag: TagType,
        tw: &mut TLVWriter,
        attr_id: u16,
    ) -> Result<(), Error> {
        let a = self
            .get_attribute(attr_id)
            .map_err(|_| Error::AttributeNotFound)?;
        if a.value != AttrValue::Custom {
            tw.put_object(tag, &a.value)
        } else {
            Err(Error::Invalid)
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
        if a.value != AttrValue::Custom {
            a.value
                .update_from_tlv(data)
                .map_err(|_| IMStatusCode::UnsupportedWrite)
        } else {
            Err(IMStatusCode::UnsupportedAttribute)
        }
    }

    pub fn write_attribute_raw(
        &mut self,
        attr_id: u16,
        value: AttrValue,
    ) -> Result<(), IMStatusCode> {
        let a = self
            .get_attribute_mut(attr_id)
            .map_err(|_| IMStatusCode::UnsupportedAttribute)?;
        a.value = value;
        Ok(())
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

    pub fn get_cluster(&mut self, cluster_id: u32) -> Result<&mut dyn ClusterType, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_mut())
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters(
        &self,
        cluster: Option<u32>,
    ) -> Result<&[Box<dyn ClusterType>], IMStatusCode> {
        let clusters = if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                &self.clusters[i..i + 1]
            } else {
                return Err(IMStatusCode::UnsupportedCluster);
            }
        } else {
            &self.clusters.as_slice()
        };
        Ok(clusters)
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters_mut(
        &mut self,
        cluster: Option<u32>,
    ) -> Result<&mut [Box<dyn ClusterType>], IMStatusCode> {
        let clusters = if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                &mut self.clusters[i..i + 1]
            } else {
                return Err(IMStatusCode::UnsupportedCluster);
            }
        } else {
            &mut self.clusters[..]
        };
        Ok(clusters)
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

    pub fn get_endpoint(&mut self, endpoint_id: u32) -> Result<&mut Box<Endpoint>, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_mut()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
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
    ) -> Result<(&[Option<Box<Endpoint>>], usize), IMStatusCode> {
        let endpoints = if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                return Err(IMStatusCode::UnsupportedEndpoint);
            }
            (&self.endpoints[e..e + 1], e)
        } else {
            (&self.endpoints[..], 0)
        };
        Ok(endpoints)
    }

    pub fn get_wildcard_endpoints_mut(
        &mut self,
        endpoint: Option<u16>,
    ) -> Result<(&mut [Option<Box<Endpoint>>], usize), IMStatusCode> {
        let endpoints = if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                return Err(IMStatusCode::UnsupportedEndpoint);
            }
            (&mut self.endpoints[e..e + 1], e)
        } else {
            (&mut self.endpoints[..], 0)
        };
        Ok(endpoints)
    }

    pub fn for_each_endpoint_mut<T>(
        &mut self,
        path: &GenericPath,
        mut f: T,
    ) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &mut Endpoint) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints_mut(path.endpoint)?;
        for e in endpoints.iter_mut() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_mut())?;
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    pub fn for_each_cluster<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints(path.endpoint)?;
        for e in endpoints.iter() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                let clusters = e.get_wildcard_clusters(path.cluster)?;
                for c in clusters.iter() {
                    f(&current_path, c.as_ref())?;
                }
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    pub fn for_each_cluster_mut<T>(
        &mut self,
        path: &GenericPath,
        mut f: T,
    ) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &mut dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints_mut(path.endpoint)?;
        for e in endpoints.iter_mut() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                let clusters = e.get_wildcard_clusters_mut(path.cluster)?;
                for c in clusters.iter_mut() {
                    f(&current_path, c.as_mut())?;
                }
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    pub fn for_each_attribute<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &dyn ClusterType) -> Result<(), IMStatusCode>,
    {
        self.for_each_cluster(path, |current_path, c| {
            let mut current_path = *current_path;
            let attributes = c
                .base()
                .get_wildcard_attribute(path.leaf.map(|at| at as u16))?;
            for a in attributes.iter() {
                current_path.leaf = Some(a.id as u32);
                f(&current_path, c)?;
            }
            Ok(())
        })
    }
}
