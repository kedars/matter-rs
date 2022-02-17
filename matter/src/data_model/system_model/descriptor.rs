use crate::data_model::objects::*;
use crate::error::*;

const CLUSTER_DESCRIPTOR_ID: u32 = 0x001D;

const ATTR_SERVERLIST_ID: u16 = 0x1;

fn attr_serverlist_new() -> Result<Box<Attribute>, Error> {
    Attribute::new(ATTR_SERVERLIST_ID, AttrValue::Uint16(1))
}

pub fn cluster_descriptor_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_DESCRIPTOR_ID)?;
    cluster.add_attribute(attr_serverlist_new()?)?;
    Ok(cluster)
}
