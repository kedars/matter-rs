use crate::error::*;

/* This file needs some major revamp. 
 * - instead of allocating all over the heap, we should use some kind of slab/block allocator
 * - instead of arrays, can use linked-lists to conserve space and avoid the internal fragmentation
 */

pub const ENDPTS_PER_ACC:     usize = 1;
pub const CLUSTERS_PER_ENDPT: usize = 4;
pub const ATTRS_PER_CLUSTER:  usize = 4;

#[derive(Debug)]
pub enum AttrValue {
    Int8(i8),
    Int64(i64),
    Uint16(u16),
    Bool(bool),
}

#[derive(Debug)]
pub struct Attribute {
    id: u32,
    value: AttrValue,
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute { id: 0, value: AttrValue::Bool(true)}
    }
}

impl Attribute {
    pub fn new (id: u32, val: AttrValue) -> Result<Box<Attribute>, Error> {
        let mut a = Box::new(Attribute::default());
        a.id = id;
        a.value = val;
        Ok(a)
    }
}

#[derive(Debug, Default)]
pub struct Cluster {
    id: u32,
    attributes: [Option<Box<Attribute>>; ATTRS_PER_CLUSTER],
}

impl Cluster {
    pub fn new (id: u32) -> Result<Box<Cluster>, Error> {
        let mut a = Box::new(Cluster::default());
        a.id = id;
        Ok(a)
    }

    pub fn add_attribute(&mut self, attr: Box<Attribute>) -> Result<(), Error> {
        for c in self.attributes.iter_mut() {
            if let None = c {
                *c = Some(attr);
                return Ok(());
            }
        }
        return Err(Error::NoSpace);
    }
}

#[derive(Debug, Default)]
pub struct Endpoint {
    id: u32,
    clusters: [Option<Box<Cluster>>; CLUSTERS_PER_ENDPT],
}

impl Endpoint {
    pub fn new (id: u32) -> Result<Box<Endpoint>, Error> {
        let mut a = Box::new(Endpoint::default());
        a.id = id;
        Ok(a)
    }

    pub fn add_cluster(&mut self, cluster: Box<Cluster>) -> Result<(), Error> {
        for c in self.clusters.iter_mut() {
            if let None = c {
                *c = Some(cluster);
                return Ok(());
            }
        }
        return Err(Error::NoSpace);
    }
}

#[derive(Debug, Default)]
pub struct Node {
    endpoints: [Option<Box<Endpoint>>; ENDPTS_PER_ACC],
}

impl Node {
    pub fn new () -> Result<Box<Node>, Error> {
        let node = Box::new(Node::default());
        Ok(node)
    }

    pub fn add_endpoint(&mut self, id: u32) -> Result<(), Error> {
        for e in self.endpoints.iter_mut() {
            if let None = e {
                let a = Endpoint::new(id)?;
                *e = Some(a);
                return Ok(());
            }
        }
        return Err(Error::NoSpace);
    }

    pub fn add_cluster(&mut self, cluster: Box<Cluster>) -> Result<(), Error> {
        if let None = self.endpoints[0] {
            self.add_endpoint(1)?;
        }
        self.endpoints[0].as_mut().unwrap().add_cluster(cluster)
    }
}
