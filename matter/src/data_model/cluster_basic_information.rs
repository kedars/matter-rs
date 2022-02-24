use super::objects::*;
use crate::{
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};

const CLUSTER_BASIC_INFORMATION_ID: u32 = 0x0028;

fn attr_interaction_model_version_new() -> Result<Box<Attribute>, Error> {
    // Id: 0, Value: 1
    Attribute::new(0, AttrValue::Uint16(1))
}

pub struct BasicInfoCluster {
    base: Cluster,
}

impl BasicInfoCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(BasicInfoCluster {
            base: Cluster::new(CLUSTER_BASIC_INFORMATION_ID),
        });
        cluster
            .base
            .add_attribute(attr_interaction_model_version_new()?)?;
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

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);
        match cmd {
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}
