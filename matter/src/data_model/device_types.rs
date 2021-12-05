use super::cluster_basic_information::*;
use super::cluster_on_off::*;
use super::objects::*;
use crate::error::*;
use std::sync::RwLockWriteGuard;

type WriteNode<'a> = RwLockWriteGuard<'a, Box<Node>>;

pub fn device_type_add_root_node(node: &mut WriteNode) -> Result<u32, Error> {
    // Add the root endpoint
    let endpoint = node.add_endpoint()?;
    if endpoint != 0 {
        // Somehow endpoint 0 was already added, this shouldn't be the case
        return Err(Error::Invalid);
    };
    // Add the mandatory clusters
    node.add_cluster(0, cluster_basic_information_new()?)?;
    Ok(endpoint)
}

pub fn device_type_add_on_off_light(node: &mut WriteNode) -> Result<u32, Error> {
    let endpoint = node.add_endpoint()?;
    node.add_cluster(endpoint, cluster_on_off_new()?)?;
    Ok(endpoint)
}
