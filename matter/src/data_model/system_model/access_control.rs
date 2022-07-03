use num_derive::FromPrimitive;

use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::core::IMStatusCode;
use crate::tlv::{TLVWriter, TagType};
use log::error;

pub const ID: u32 = 0x001F;

// Some placeholder values
const SUBJECTS_PER_ENTRY: u16 = 3;
const TARGETS_PER_ENTRY: u16 = 3;
const ENTRIES_PER_FABRIC: u16 = 3;

#[derive(FromPrimitive)]
enum Attributes {
    Acl = 0,
    Extension = 1,
    SubjectsPerEntry = 2,
    TargetsPerEntry = 3,
    EntriesPerFabric = 4,
}

pub struct AccessControlCluster {
    base: Cluster,
}

impl AccessControlCluster {
    pub fn new() -> Result<Box<Self>, Error> {
        let mut c = Box::new(AccessControlCluster {
            base: Cluster::new(ID)?,
        });
        c.base.add_attribute(attr_acl_new()?)?;
        c.base.add_attribute(attr_extension_new()?)?;
        c.base.add_attribute(attr_subjects_per_entry_new()?)?;
        c.base.add_attribute(attr_targets_per_entry_new()?)?;
        c.base.add_attribute(attr_entries_per_fabric_new()?)?;
        Ok(c)
    }
}

impl ClusterType for AccessControlCluster {
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
    ) -> Result<(), IMStatusCode> {
        match num::FromPrimitive::from_u16(attr_id).ok_or(IMStatusCode::UnsupportedAttribute)? {
            Attributes::Acl => {
                // Empty for now
                let _ = tw.start_array(tag);
                let _ = tw.end_container();
            }
            Attributes::Extension => {
                // Empty for now
                let _ = tw.start_array(tag);
                let _ = tw.end_container();
            }
            _ => {
                error!("Not yet supported");
                return Err(IMStatusCode::UnsupportedAttribute);
            }
        }
        Ok(())
    }
}

fn attr_acl_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::Acl as u16,
        AttrValue::Custom,
        Access::RWFA,
        Quality::NONE,
    )
}

fn attr_extension_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::Extension as u16,
        AttrValue::Custom,
        Access::RWFA,
        Quality::NONE,
    )
}

fn attr_subjects_per_entry_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::SubjectsPerEntry as u16,
        AttrValue::Uint16(SUBJECTS_PER_ENTRY),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_targets_per_entry_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::TargetsPerEntry as u16,
        AttrValue::Uint16(TARGETS_PER_ENTRY),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_entries_per_fabric_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::EntriesPerFabric as u16,
        AttrValue::Uint16(ENTRIES_PER_FABRIC),
        Access::RV,
        Quality::FIXED,
    )
}
