use num_derive::FromPrimitive;

use crate::data_model::core::DataModel;
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::command::CommandReq;
use crate::interaction_model::core::IMStatusCode;
use crate::interaction_model::messages::GenericPath;
use crate::tlv::TLVElement;
use crate::tlv_common::TagType;
use crate::tlv_writer::TLVWriter;
use log::error;

pub const ID: u32 = 0x001D;

#[derive(FromPrimitive)]
enum Attributes {
    DeviceTypeList = 0,
    ServerList = 1,
    ClientList = 2,
    PartsList = 3,
}

pub struct DescriptorCluster {
    base: Cluster,
    endpoint_id: u16,
    data_model: DataModel,
}

impl DescriptorCluster {
    pub fn new(endpoint_id: u16, data_model: DataModel) -> Result<Box<Self>, Error> {
        let mut c = Box::new(DescriptorCluster {
            endpoint_id,
            data_model,
            base: Cluster::new(ID)?,
        });
        c.base.add_attribute(attr_serverlist_new()?)?;
        Ok(c)
    }
}

impl ClusterType for DescriptorCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(
        &self,
        tag: TagType,
        tw: &mut TLVWriter,
        attr_id: u16,
    ) -> Result<(), Error> {
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
                    tw.put_u32(TagType::Anonymous, c.base().id())
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

    fn write_attribute(&mut self, data: &TLVElement, attr_id: u16) -> Result<(), IMStatusCode> {
        self.base.write_attribute(data, attr_id)
    }

    fn handle_command(&mut self, _cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        // NocCommand to handle
        Ok(())
    }
}

fn attr_serverlist_new() -> Result<Box<Attribute>, Error> {
    Attribute::new(
        Attributes::ServerList as u16,
        AttrValue::Custom,
        Access::RV,
        Quality::NONE,
    )
}
