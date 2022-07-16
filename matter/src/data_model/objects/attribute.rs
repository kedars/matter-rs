use super::GlobalElements;
use crate::{
    error::*,
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
    tlv::{TLVElement, TLVWriter, TagType, ToTLV},
};
use bitflags::bitflags;
use log::error;
use std::fmt::{self, Debug, Formatter};

bitflags! {
    #[derive(Default)]
    pub struct Access: u16 {
        const READ = 0x0001;
        const WRITE = 0x0002;
        const FAB_SCOPED = 0x0004;
        const FAB_SENSITIVE = 0x0008;
        const NEED_VIEW = 0x0010;
        const NEED_OPERATE = 0x0020;
        const NEED_MANAGE = 0x0040;
        const NEED_ADMIN = 0x0080;
        const TIMED_ONLY = 0x0100;
        const RV = Self::READ.bits | Self::NEED_VIEW.bits;
        const RWVA = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_ADMIN.bits;
        const RWFA = Self::READ.bits | Self::WRITE.bits | Self::FAB_SCOPED.bits | Self::NEED_ADMIN.bits;
        const RWVM = Self::READ.bits | Self::WRITE.bits | Self::NEED_VIEW.bits | Self::NEED_MANAGE.bits;
    }
}

bitflags! {
    #[derive(Default)]
    pub struct Quality: u8 {
        const NONE = 0x00;
        const SCENE = 0x01;
        const PERSISTENT = 0x02;
        const FIXED = 0x03;
        const NULLABLE = 0x04;
    }
}

/* This file needs some major revamp.
 * - instead of allocating all over the heap, we should use some kind of slab/block allocator
 * - instead of arrays, can use linked-lists to conserve space and avoid the internal fragmentation
 */

#[derive(PartialEq, Copy, Clone)]
pub enum AttrValue {
    Int64(i64),
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Bool(bool),
    Custom,
}

impl Debug for AttrValue {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            AttrValue::Int64(v) => write!(f, "{:?}", *v),
            AttrValue::Uint8(v) => write!(f, "{:?}", *v),
            AttrValue::Uint16(v) => write!(f, "{:?}", *v),
            AttrValue::Uint32(v) => write!(f, "{:?}", *v),
            AttrValue::Uint64(v) => write!(f, "{:?}", *v),
            AttrValue::Bool(v) => write!(f, "{:?}", *v),
            AttrValue::Custom => write!(f, "custom-attribute"),
        }?;
        Ok(())
    }
}

impl ToTLV for AttrValue {
    fn to_tlv(&self, tw: &mut TLVWriter, tag_type: TagType) -> Result<(), Error> {
        // What is the time complexity of such long match statements?
        match self {
            AttrValue::Bool(v) => tw.bool(tag_type, *v),
            AttrValue::Uint8(v) => tw.u8(tag_type, *v),
            AttrValue::Uint16(v) => tw.u16(tag_type, *v),
            AttrValue::Uint32(v) => tw.u32(tag_type, *v),
            AttrValue::Uint64(v) => tw.u64(tag_type, *v),
            _ => {
                error!("Attribute type not yet supported");
                Err(Error::AttributeNotFound)
            }
        }
    }
}

impl AttrValue {
    pub fn update_from_tlv(&mut self, tr: &TLVElement) -> Result<(), Error> {
        match self {
            AttrValue::Bool(v) => *v = tr.bool()?,
            AttrValue::Uint8(v) => *v = tr.u8()?,
            AttrValue::Uint16(v) => *v = tr.u16()?,
            AttrValue::Uint32(v) => *v = tr.u32()?,
            AttrValue::Uint64(v) => *v = tr.u64()?,
            _ => {
                error!("Attribute type not yet supported");
                return Err(Error::AttributeNotFound);
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct Attribute {
    pub(super) id: u16,
    pub(super) value: AttrValue,
    pub(super) quality: Quality,
    pub(super) access: Access,
}

impl Default for Attribute {
    fn default() -> Attribute {
        Attribute {
            id: 0,
            value: AttrValue::Bool(true),
            quality: Default::default(),
            access: Default::default(),
        }
    }
}

impl Attribute {
    pub fn new(
        id: u16,
        value: AttrValue,
        access: Access,
        quality: Quality,
    ) -> Result<Attribute, Error> {
        Ok(Attribute {
            id,
            value,
            access,
            quality,
        })
    }

    pub fn set_value(&mut self, value: AttrValue) -> Result<(), Error> {
        if !self.quality.contains(Quality::FIXED) {
            self.value = value;
            Ok(())
        } else {
            Err(Error::Invalid)
        }
    }

    pub fn is_system_attr(attr_id: u16) -> bool {
        attr_id >= (GlobalElements::ServerGenCmd as u16)
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.id, self.value)
    }
}
