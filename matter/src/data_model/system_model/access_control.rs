use std::sync::Arc;

use num_derive::FromPrimitive;

use crate::acl::{self, AclEntry, AclMgr};
use crate::data_model::objects::*;
use crate::error::*;
use crate::interaction_model::core::IMStatusCode;
use crate::tlv::{FromTLV, TLVElement, TagType, ToTLV};
use log::{error, info};

pub const ID: u32 = 0x001F;

#[derive(FromPrimitive)]
pub enum Attributes {
    Acl = 0,
    Extension = 1,
    SubjectsPerEntry = 2,
    TargetsPerEntry = 3,
    EntriesPerFabric = 4,
}

pub struct AccessControlCluster {
    base: Cluster,
    acl_mgr: Arc<AclMgr>,
}

impl AccessControlCluster {
    pub fn new(acl_mgr: Arc<AclMgr>) -> Result<Box<Self>, Error> {
        let mut c = Box::new(AccessControlCluster {
            base: Cluster::new(ID)?,
            acl_mgr,
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

    fn read_custom_attribute(&self, encoder: &mut dyn Encoder, attr: AttrDetails) {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::Acl) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                // Empty for now
                let _ = tw.start_array(tag);
                let _ = self.acl_mgr.for_each_acl(|entry| {
                    let _ = entry.to_tlv(tw, TagType::Anonymous);
                });
                let _ = tw.end_container();
            })),
            Some(Attributes::Extension) => encoder.encode(EncodeValue::Closure(&|tag, tw| {
                // Empty for now
                let _ = tw.start_array(tag);
                let _ = tw.end_container();
            })),
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
            }
        }
    }

    fn write_attribute(
        &mut self,
        attr: AttrDetails,
        data: &TLVElement,
    ) -> Result<(), IMStatusCode> {
        match num::FromPrimitive::from_u16(attr.attr_id) {
            Some(Attributes::Acl) => {
                // TODO: Need to support all modes of 'List'
                let acl_entry =
                    AclEntry::from_tlv(data).map_err(|_| IMStatusCode::ConstraintError)?;
                match self.acl_mgr.add(acl_entry) {
                    Ok(_) => {
                        info!("New ACL Added {:?}", acl_entry);
                        Ok(())
                    }
                    Err(Error::NoSpace) => Err(IMStatusCode::ResourceExhausted),
                    _ => Err(IMStatusCode::ConstraintError),
                }
            }
            _ => {
                error!("Attribute not yet supported: this shouldn't happen");
                Err(IMStatusCode::NotFound)
            }
        }
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
        AttrValue::Uint16(acl::SUBJECTS_PER_ENTRY as u16),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_targets_per_entry_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::TargetsPerEntry as u16,
        AttrValue::Uint16(acl::TARGETS_PER_ENTRY as u16),
        Access::RV,
        Quality::FIXED,
    )
}

fn attr_entries_per_fabric_new() -> Result<Attribute, Error> {
    Attribute::new(
        Attributes::EntriesPerFabric as u16,
        AttrValue::Uint16(acl::ENTRIES_PER_FABRIC as u16),
        Access::RV,
        Quality::FIXED,
    )
}
