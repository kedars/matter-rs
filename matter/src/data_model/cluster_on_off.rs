use super::objects::*;
use crate::{
    cmd_enter,
    error::*,
    interaction_model::{command::CommandReq, core::IMStatusCode},
    tlv::TLVElement,
    tlv_common::TagType,
    tlv_writer::TLVWriter,
};
use log::info;
use num_derive::FromPrimitive;

pub const ID: u32 = 0x0006;

pub enum Attributes {
    OnOff = 0x0,
}

#[derive(FromPrimitive)]
pub enum Commands {
    Off = 0x0,
    On = 0x01,
    Toggle = 0x02,
}

fn attr_on_off_new() -> Result<Box<Attribute>, Error> {
    // OnOff, Value: false
    Attribute::new(
        Attributes::OnOff as u16,
        AttrValue::Bool(false),
        Access::RV,
        Quality::PERSISTENT,
    )
}

pub struct OnOffCluster {
    base: Cluster,
}

impl OnOffCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut cluster = Box::new(OnOffCluster {
            base: Cluster::new(ID)?,
        });
        cluster.base.add_attribute(attr_on_off_new()?)?;
        Ok(cluster)
    }
}

impl ClusterType for OnOffCluster {
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

    fn handle_command(&mut self, cmd_req: &mut CommandReq) -> Result<(), IMStatusCode> {
        let cmd = cmd_req
            .cmd
            .path
            .leaf
            .map(|c| num::FromPrimitive::from_u32(c))
            .ok_or(IMStatusCode::UnsupportedCommand)?
            .ok_or(IMStatusCode::UnsupportedCommand)?;
        match cmd {
            Commands::Off => {
                cmd_enter!("Off");
                let value = self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap();
                if AttrValue::Bool(true) == *value {
                    self.base
                        .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(false))
                        .map_err(|_| IMStatusCode::Failure)?;
                }
                cmd_req.trans.complete();
                Err(IMStatusCode::Sucess)
            }
            Commands::On => {
                cmd_enter!("On");
                let value = self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap();
                if AttrValue::Bool(false) == *value {
                    self.base
                        .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(true))
                        .map_err(|_| IMStatusCode::Failure)?;
                }

                cmd_req.trans.complete();
                Err(IMStatusCode::Sucess)
            }
            Commands::Toggle => {
                cmd_enter!("Toggle");
                let value = match self
                    .base
                    .read_attribute_raw(Attributes::OnOff as u16)
                    .unwrap()
                {
                    &AttrValue::Bool(v) => v,
                    _ => false,
                };
                self.base
                    .write_attribute_raw(Attributes::OnOff as u16, AttrValue::Bool(!value))
                    .map_err(|_| IMStatusCode::Failure)?;
                cmd_req.trans.complete();
                Err(IMStatusCode::Sucess)
            }
        }
    }
}
