use crate::{
    data_model::objects::{Cluster, ClusterType},
    error::Error,
};

pub const ID: u32 = 0x0031;

pub struct NwCommCluster {
    base: Cluster,
}

impl ClusterType for NwCommCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}

enum FeatureMap {
    _Wifi = 0,
    _Thread = 1,
    Ethernet = 2,
}

impl NwCommCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut c = Box::new(Self {
            base: Cluster::new(ID)?,
        });
        // TODO: Arch-Specific
        c.base.set_feature_map(FeatureMap::Ethernet as u32)?;
        Ok(c)
    }
}
