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

pub struct BasicInfoCluster {}
impl ClusterType for BasicInfoCluster {
    fn read_attribute(
        &self,
        _tag: TagType,
        _tw: &mut TLVWriter,
        _attr_id: u16,
    ) -> Result<(), Error> {
        // No custom attributes
        Ok(())
    }

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req.cmd.path.leaf.map(|a| a as u16);
        println!("Received command: {:?}", cmd);
        match cmd {
            _ => Err(IMStatusCode::UnsupportedCommand),
        }
    }
}

pub fn cluster_basic_information_new() -> Result<Box<Cluster>, Error> {
    let mut cluster = Cluster::new(CLUSTER_BASIC_INFORMATION_ID, Box::new(BasicInfoCluster {}));
    cluster.add_attribute(attr_interaction_model_version_new()?)?;
    Ok(cluster)
}
