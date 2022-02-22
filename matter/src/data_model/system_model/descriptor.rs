use num_derive::FromPrimitive;

use crate::data_model::core::DataModel;
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::command::CommandReq;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::GenericPath;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use log::error;

const CLUSTER_DESCRIPTOR_ID: u32 = 0x001D;

#[derive(FromPrimitive)]
enum Attributes {
    DeviceTypeList = 0,
    ServerList = 1,
    ClientList = 2,
    PartsList = 3,
}

struct DescriptorCluster {
    endpoint_id: u16,
    data_model: DataModel,
}

impl ClusterType for DescriptorCluster {
    fn read_attribute(&self, tag: TagType, tw: &mut TLVWriter, attr_id: u16) -> Result<(), Error> {
        match num::FromPrimitive::from_u16(attr_id).ok_or(Error::Invalid)? {
            Attributes::ServerList => {
                let path = GenericPath {
                    endpoint: Some(self.endpoint_id),
                    cluster: None,
                    leaf: None,
                };
                tw.put_start_array(tag)?;
                let dm = self.data_model.node.read().unwrap();
                dm.for_each_cluster(&path, |_current_path, c| {
                    tw.put_u32(TagType::Anonymous, c.id())
                        .map_err(|_| crate::interaction_model::core::IMStatusCode::Failure)
                })
                .map_err(|_| Error::Invalid)?;
                tw.put_end_container()?;
            }
            _ => {
                error!("Not yet supported");
                return Err(Error::AttributeNotFound);
            }
        }
        Ok(())
    }

    fn handle_command(&mut self, _cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        // NocCommand to handle
        Ok(())
    }
}

fn attr_serverlist_new() -> Result<Box<Attribute>, Error> {
    Attribute::new(Attributes::ServerList as u16, AttrValue::Custom)
}

pub fn cluster_descriptor_new(
    endpoint_id: u16,
    data_model: DataModel,
) -> Result<Box<Cluster>, Error> {
    let descriptor = Box::new(DescriptorCluster {
        endpoint_id,
        data_model,
    });
    let mut cluster = Cluster::new(CLUSTER_DESCRIPTOR_ID, descriptor);

    cluster.add_attribute(attr_serverlist_new()?)?;
    Ok(cluster)
}
