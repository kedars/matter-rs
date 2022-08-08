use num_derive::FromPrimitive;

use crate::data_model::core::DataModel;
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::messages::GenericPath;
use crate::tlv::{TLVWriter, TagType};
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

    fn encode_server_list(&self, tag: TagType, tw: &mut TLVWriter) {
        let path = GenericPath {
            endpoint: Some(self.endpoint_id),
            cluster: None,
            leaf: None,
        };
        let _ = tw.start_array(tag);
        let dm = self.data_model.node.read().unwrap();
        let _ = dm.for_each_cluster(&path, |_current_path, c| {
            let _ = tw.u32(TagType::Anonymous, c.base().id());
            Ok(())
        });
        let _ = tw.end_container();
    }
}

impl ClusterType for DescriptorCluster {
    fn base(&self) -> &Cluster {
        &self.base
    }
    fn base_mut(&mut self) -> &mut Cluster {
        &mut self.base
    }

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::ServerList) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                self.encode_server_list(tag, tw)
            })),

            _ => {
                error!("Attribute not supported: this shouldn't happen");
            }
        }
    }
}

fn attr_serverlist_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::ServerList as u16,
        AttrValue::Custom,
        Access::RV,
        Quality::NONE,
    )
}
