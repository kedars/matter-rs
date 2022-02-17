use super::cluster_basic_information::*;
use super::cluster_on_off::*;
use super::objects::*;
use super::sdm::dev_att::DevAttDataFetcher;
use super::sdm::general_commissioning::cluster_general_commissioning_new;
use super::sdm::noc::cluster_operational_credentials_new;
use super::system_model::descriptor::cluster_descriptor_new;
use crate::error::*;
use crate::fabric::FabricMgr;
use std::sync::Arc;
use std::sync::RwLockWriteGuard;

type WriteNode<'a> = RwLockWriteGuard<'a, Box<Node>>;

pub fn device_type_add_root_node(
    node: &mut WriteNode,
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
) -> Result<u32, Error> {
    // Add the root endpoint
    let endpoint = node.add_endpoint()?;
    if endpoint != 0 {
        // Somehow endpoint 0 was already added, this shouldn't be the case
        return Err(Error::Invalid);
    };
    // Add the mandatory clusters
    node.add_cluster(0, cluster_basic_information_new()?)?;
    node.add_cluster(0, cluster_descriptor_new()?)?;
    let (general_commissioning, failsafe) = cluster_general_commissioning_new()?;
    node.add_cluster(0, general_commissioning)?;
    node.add_cluster(
        0,
        cluster_operational_credentials_new(dev_att, fabric_mgr, failsafe)?,
    )?;
    Ok(endpoint)
}

pub fn device_type_add_on_off_light(node: &mut WriteNode) -> Result<u32, Error> {
    let endpoint = node.add_endpoint()?;
    node.add_cluster(endpoint, cluster_on_off_new()?)?;
    Ok(endpoint)
}
