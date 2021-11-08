use crate::error::*;
use super::objects::*;

const CLUSTER_ONOFF_ID: u32 = 0x0006;

fn attr_on_off_new() -> Result<Box<Attribute>, Error> {
    // Id: 0, Value: false
    Attribute::new(0, AttrValue::Bool(false))
}

pub fn cluster_on_off_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_ONOFF_ID)?;
    cluster.add_attribute(attr_on_off_new()?)?;
    Ok(cluster)
}