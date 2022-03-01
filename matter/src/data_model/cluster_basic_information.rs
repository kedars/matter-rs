use super::objects::*;
use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

const CLUSTER_BASIC_INFORMATION_ID: u32 = 0x0028;
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

fn attr_vid_new(vid: u16) -> Result<Box<Attribute>, Error> {
    Attribute::new(Attributes::VendorId as u16, AttrValue::Uint16(vid))
}

fn attr_pid_new(pid: u16) -> Result<Box<Attribute>, Error> {
    Attribute::new(Attributes::ProductId as u16, AttrValue::Uint16(pid))
}

fn attr_hw_ver_new(hw_ver: u16) -> Result<Box<Attribute>, Error> {
    Attribute::new(Attributes::HwVer as u16, AttrValue::Uint16(hw_ver))
}

fn attr_sw_ver_new(sw_ver: u32) -> Result<Box<Attribute>, Error> {
    Attribute::new(Attributes::SwVer as u16, AttrValue::Uint32(sw_ver))
}

pub struct BasicInfoCluster {
    base: Cluster,
}

impl BasicInfoCluster {
    pub fn new(cfg: BasicInfoConfig) -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(BasicInfoCluster {
            base: Cluster::new(CLUSTER_BASIC_INFORMATION_ID),
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

    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error> {
        self.base.read_attribute(tag, tw, attr_id)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);
        match cmd {
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}
