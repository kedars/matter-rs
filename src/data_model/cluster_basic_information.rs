use super::objects::*;
use crate::error::*;

const CLUSTER_BASIC_INFORMATION_ID: u32 = 0x0028;

fn attr_interaction_model_version_new() -> Result<Box<Attribute>, Error> {
    // Id: 0, Value: 1
    Attribute::new(0, AttrValue::Uint16(1))
}

pub fn cluster_basic_information_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_BASIC_INFORMATION_ID)?;
    cluster.add_attribute(attr_interaction_model_version_new()?)?;
    Ok(cluster)
}
