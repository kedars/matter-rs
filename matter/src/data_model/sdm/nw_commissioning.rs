use crate::{
    data_model::objects::{Cluster, ClusterType},
    error::Error,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
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

    fn read_custom_attribute(
        &self,
        _tag: TagType,
        _tw: &mut TLVWriter,
        _attr_id: u16,
    ) -> Result<(), Error> {
        Err(Error::Invalid)
    }

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, _cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        Ok(())
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
