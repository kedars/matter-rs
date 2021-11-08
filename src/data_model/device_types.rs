use std::sync::RwLockWriteGuard;
use crate::error::*;
use super::objects::*;
use super::cluster_basic_information::*;
use super::cluster_on_off::*;

type WriteNode<'a> = RwLockWriteGuard<'a, Box<Node>>;

pub fn device_type_add_root_node(node: &mut WriteNode) -> Result<(), Error> {
    // Add the root endpoint
    node.add_endpoint(0)?;
    // Add the mandatory clusters
    node.add_cluster(cluster_basic_information_new()?)?;
    Ok(())
}

pub fn device_type_add_on_off_light(endpoint_id: u32, node: &mut WriteNode) -> Result<(), Error> {
    node.add_cluster(cluster_on_off_new()?)?;
    Ok(())
}
