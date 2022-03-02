use crate::{
    data_model::objects::{Cluster, ClusterType},
    error::Error,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
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

    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error> {
        self.base.read_attribute(tag, tw, attr_id)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, _cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        Ok(())
    }
}

impl TemplateCluster {
    pub fn new() -> Result<Self, Error> {
        Ok(Self {
            base: Cluster::new(CLUSTER_NETWORK_COMMISSIONING_ID)?,
        })
    }
}
