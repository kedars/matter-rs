use std::sync::RwLock;

use crate::{cert::Cert, error::Error, pki::pki::KeyPair};

#[allow(dead_code)]
pub struct Fabric {
    node_id: u64,
    fabric_id: u64,
    key_pair: KeyPair,
    root_ca: Cert,
    icac: Cert,
    noc: Cert,
    ipk: Cert,
}

impl Fabric {
    pub fn new(
        key_pair: KeyPair,
        root_ca: Cert,
        icac: Cert,
        noc: Cert,
        ipk: Cert,
    ) -> Result<Self, Error> {
        let node_id = noc.get_node_id()?;
        let fabric_id = noc.get_fabric_id()?;
        Ok(Self {
            node_id,
            fabric_id,
            key_pair,
            root_ca,
            icac,
            noc,
            ipk,
        })
    }

    pub fn dummy() -> Result<Self, Error> {
        Ok(Self {
            node_id: 0,
            fabric_id: 0,
            key_pair: KeyPair::dummy()?,
            root_ca: Cert::default(),
            icac: Cert::default(),
            noc: Cert::default(),
            ipk: Cert::default(),
        })
    }
}

const MAX_SUPPORTED_FABRICS: usize = 3;
#[derive(Default)]
struct FabricMgrInner {
    // The outside world expects Fabric Index to be one more than the actual one
    // since 0 is not allowed. Need to handle this cleanly somehow
    pub fabrics: [Option<Fabric>; MAX_SUPPORTED_FABRICS],
}

pub struct FabricMgr(RwLock<FabricMgrInner>);

impl FabricMgr {
    pub fn new() -> Result<Self, Error> {
        let dummy_fabric = Fabric::dummy()?;
        let mut mgr = FabricMgrInner::default();
        mgr.fabrics[0] = Some(dummy_fabric);
        Ok(Self(RwLock::new(mgr)))
    }

    pub fn add(&self, f: Fabric) -> Result<u8, Error> {
        let mut mgr = self.0.write()?;
        let index = mgr
            .fabrics
            .iter()
            .position(|f| f.is_none())
            .ok_or(Error::NoSpace)?;
        mgr.fabrics[index] = Some(f);
        Ok(index as u8)
    }
}
