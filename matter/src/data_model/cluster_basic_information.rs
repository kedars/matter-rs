use super::objects::*;
use crate::error::*;

pub const ID: u32 = 0x0028;
enum Attributes {
    VendorId = 2,
    ProductId = 4,
    HwVer = 7,
    SwVer = 9,
}

pub struct BasicInfoConfig {
    pub vid: u16,
    pub pid: u16,
    pub hw_ver: u16,
    pub sw_ver: u32,
}

fn attr_vid_new(vid: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::VendorId as u16,
        AttrValue::Uint16(vid),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_pid_new(pid: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::ProductId as u16,
        AttrValue::Uint16(pid),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_hw_ver_new(hw_ver: u16) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::HwVer as u16,
        AttrValue::Uint16(hw_ver),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_sw_ver_new(sw_ver: u32) -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::SwVer as u16,
        AttrValue::Uint32(sw_ver),
        Access::RV,
        Quality::FIXED,
    )
}

pub struct BasicInfoCluster {
    base: Cluster,
}

impl BasicInfoCluster {
    pub fn new(cfg: BasicInfoConfig) -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(BasicInfoCluster {
            base: Cluster::new(ID)?,
        });
        cluster.base.add_attribute(attr_vid_new(cfg.vid)?)?;
        cluster.base.add_attribute(attr_pid_new(cfg.pid)?)?;
        cluster.base.add_attribute(attr_hw_ver_new(cfg.hw_ver)?)?;
        cluster.base.add_attribute(attr_sw_ver_new(cfg.sw_ver)?)?;
        Ok(cluster)
    }
}

impl ClusterType for BasicInfoCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }
}
