use crate::{
    data_model::objects::{Cluster, ClusterType},
    error::Error,
};

const CLUSTER_NETWORK_COMMISSIONING_ID: u32 = 0x0031;

pub struct TemplateCluster {
    base: Cluster,
}

impl ClusterType for TemplateCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}

impl TemplateCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        Ok(Box::new(Self {
            base: Cluster::new(CLUSTER_NETWORK_COMMISSIONING_ID)?,
        }))
    }
}
