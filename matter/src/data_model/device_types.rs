use super::cluster_basic_information::BasicInfoCluster;
use super::cluster_basic_information::BasicInfoConfig;
use super::cluster_on_off::OnOffCluster;
use super::objects::*;
use super::sdm::dev_att::DevAttDataFetcher;
use super::sdm::general_commissioning::GenCommCluster;
use super::sdm::noc::NocCluster;
use super::sdm::nw_commissioning::NwCommCluster;
use super::system_model::access_control::AccessControlCluster;
use crate::acl::AclMgr;
use crate::error::*;
use crate::fabric::FabricMgr;
use std::sync::Arc;
use std::sync::RwLockWriteGuard;

type WriteNode<'a> = RwLockWriteGuard<'a, Box<Node>>;

pub fn device_type_add_root_node(
    node: &mut WriteNode,
    dev_info: BasicInfoConfig,
    dev_att: Box<dyn DevAttDataFetcher>,
    fabric_mgr: Arc<FabricMgr>,
    acl_mgr: Arc<AclMgr>,
) -> Result<u32, Error> {
    // Add the root endpoint
    let endpoint = node.add_endpoint()?;
    if endpoint != 0 {
        // Somehow endpoint 0 was already added, this shouldn't be the case
        return Err(Error::Invalid);
    };
    // Add the mandatory clusters
    node.add_cluster(0, BasicInfoCluster::new(dev_info)?)?;
    let general_commissioning = GenCommCluster::new()?;
    let failsafe = general_commissioning.failsafe();
    node.add_cluster(0, general_commissioning)?;
    node.add_cluster(0, NwCommCluster::new()?)?;
    node.add_cluster(
        0,
        NocCluster::new(dev_att, fabric_mgr, acl_mgr.clone(), failsafe)?,
    )?;
    node.add_cluster(0, AccessControlCluster::new(acl_mgr)?)?;
    Ok(endpoint)
}

pub fn device_type_add_on_off_light(node: &mut WriteNode) -> Result<u32, Error> {
    let endpoint = node.add_endpoint()?;
    node.add_cluster(endpoint, OnOffCluster::new()?)?;
    Ok(endpoint)
}
