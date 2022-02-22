use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode, messages::GenericPath},
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
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
    Bool(bool),
    Custom,
}

impl Debug for AttrValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            AttrValue::Int8(v) => write!(f, "{:?}", *v),
            AttrValue::Int64(v) => write!(f, "{:?}", *v),
            AttrValue::Uint16(v) => write!(f, "{:?}", *v),
            AttrValue::Bool(v) => write!(f, "{:?}", *v),
            AttrValue::Custom => write!(f, "custom-attribute"),
        }?;
        Ok(())
    }
}

impl ToTLV for AttrValue {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        match self {
            AttrValue::Bool(v) => tw.put_bool(tag_type, *v),
            AttrValue::Uint16(v) => tw.put_u16(tag_type, *v),
            _ => {
                error!("Not yet supported");
                Ok(())
            }
        }
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
    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error>;
    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode>;
}

pub struct Cluster {
    id: u32,
    attributes: [Option<Box<Attribute>>; ATTRS_PER_CLUSTER],
    c: Box<dyn ClusterType>,
}

impl Cluster {
    pub fn new(id: u32, c: Box<dyn ClusterType>) -> Box<Cluster> {
        Box::new(Cluster {
            id,
            attributes: Default::default(),
            c,
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn add_attribute(&mut self, attr: Box<Attribute>) -> Result<(), Error> {
        for c in self.attributes.iter_mut() {
            if c.is_none() {
                *c = Some(attr);
                return Ok(());
            }
        }
        Err(Error::NoSpace)
    }

    pub fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        self.c.handle_command(cmd_req)
    }

    fn get_attribute_index(&self, attr_id: u16) -> Option<usize> {
        self.attributes
            .iter()
            .position(|x| x.as_ref().map_or(false, |c| c.id == attr_id))
    }

    fn get_attribute(&self, attr_id: u16) -> Option<&Box<Attribute>> {
        for a in &self.attributes {
            if a.as_ref().map_or(false, |c| c.id == attr_id) {
                return a.as_ref();
            }
        }
        None
    }

    // Returns a slice of attribute, with either a single attribute or all (wildcard)
    pub fn get_wildcard_attribute(
        &self,
        attribute: Option<u16>,
    ) -> Result<&[Option<Box<Attribute>>], IMStatusCode> {
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
        if let Some(a) = self.get_attribute(attr_id) {
            if a.value == AttrValue::Custom {
                self.c.read_attribute(tag, tw, attr_id)
            } else {
                tw.put_object(tag, &a.value)
            }
        } else {
            Err(Error::AttributeNotFound)
        }
    }
}

impl std::fmt::Display for Cluster {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}, ", self.id)?;
        write!(f, "attrs[")?;
        let mut comma = "";
        for element in self.attributes.iter() {
            if let Some(e) = element {
                write!(f, "{} {}", comma, e)?;
            }
            comma = ",";
        }
        write!(f, " ], ")
    }
}

#[derive(Default)]
pub struct Endpoint {
    clusters: [Option<Box<Cluster>>; CLUSTERS_PER_ENDPT],
}

impl Endpoint {
    pub fn new() -> Result<Box<Endpoint>, Error> {
        Ok(Box::new(Endpoint::default()))
    }

    pub fn add_cluster(&mut self, cluster: Box<Cluster>) -> Result<(), Error> {
        for c in self.clusters.iter_mut() {
            if c.is_none() {
                *c = Some(cluster);
                return Ok(());
            }
        }
        Err(Error::NoSpace)
    }

    fn get_cluster_index(&self, cluster_id: u32) -> Option<usize> {
        self.clusters
            .iter()
            .position(|x| x.as_ref().map_or(false, |c| c.id == cluster_id))
    }

    pub fn get_cluster(&mut self, cluster_id: u32) -> Result<&mut Box<Cluster>, Error> {
        let index = self
            .get_cluster_index(cluster_id)
            .ok_or(Error::ClusterNotFound)?;
        Ok(self.clusters[index].as_mut().unwrap())
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters(
        &self,
        cluster: Option<u32>,
    ) -> Result<&[Option<Box<Cluster>>], IMStatusCode> {
        let clusters = if let Some(c) = cluster {
            if let Some(i) = self.get_cluster_index(c) {
                &self.clusters[i..i + 1]
            } else {
                return Err(IMStatusCode::UnsupportedCluster);
            }
        } else {
            &self.clusters[..]
        };
        Ok(clusters)
    }

    // Returns a slice of clusters, with either a single cluster or all (wildcard)
    pub fn get_wildcard_clusters_mut(
        &mut self,
        cluster: Option<u32>,
    ) -> Result<&mut [Option<Box<Cluster>>], IMStatusCode> {
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
        for element in self.clusters.iter().flatten() {
            write!(f, "{} {{ {} }}", comma, element)?;
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

    pub fn add_cluster(&mut self, endpoint_id: u32, cluster: Box<Cluster>) -> Result<(), Error> {
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

    pub fn for_each_cluster<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &Cluster) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints(path.endpoint)?;
        for e in endpoints.iter().flatten() {
            current_path.endpoint = Some(endpoint_id as u16);
            let clusters = e.get_wildcard_clusters(path.cluster)?;
            for c in clusters.iter().flatten() {
                f(&current_path, c)?;
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
        T: FnMut(&GenericPath, &mut Cluster) -> Result<(), IMStatusCode>,
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints_mut(path.endpoint)?;
        for e in endpoints.iter_mut().flatten() {
            current_path.endpoint = Some(endpoint_id as u16);
            let clusters = e.get_wildcard_clusters_mut(path.cluster)?;
            for c in clusters.iter_mut().flatten() {
                f(&current_path, c)?;
            }
            endpoint_id += 1;
        }
        Ok(())
    }

    pub fn for_each_attribute<T>(&self, path: &GenericPath, mut f: T) -> Result<(), IMStatusCode>
    where
        T: FnMut(&GenericPath, &Cluster) -> Result<(), IMStatusCode>,
    {
        self.for_each_cluster(path, |current_path, c| {
            let mut current_path = *current_path;
            let attributes = c.get_wildcard_attribute(path.leaf.map(|at| at as u16))?;
            for a in attributes.iter().flatten() {
                current_path.leaf = Some(a.id as u32);
                f(&current_path, c)?;
            }
            Ok(())
        })
    }
}
