use std::sync::RwLock;

use crate::{
    error::Error,
    fabric,
    interaction_model::messages::GenericPath,
    tlv::{FromTLV, TLVElement, TLVWriter, TagType, ToTLV},
};
use bitflags::bitflags;
use log::error;
use num_derive::FromPrimitive;

// Matter Minimum Requirements
pub const SUBJECTS_PER_ENTRY: usize = 4;
pub const TARGETS_PER_ENTRY: usize = 3;
pub const ENTRIES_PER_FABRIC: usize = 3;

bitflags! {
    #[derive(Default)]
    pub struct Privilege: u8 {
        const VIEW = 0x01;
        const OPERATE = 0x02;
        const MANAGE = 0x04;
        const ADMIN = 0x08;
    }
}

fn unfurl(privilege: Privilege) -> Privilege {
    if privilege.contains(Privilege::ADMIN) {
        Privilege::ADMIN | Privilege::OPERATE | Privilege::MANAGE | Privilege::VIEW
    } else if privilege.contains(Privilege::OPERATE) {
        Privilege::OPERATE | Privilege::MANAGE | Privilege::VIEW
    } else if privilege.contains(Privilege::MANAGE) {
        Privilege::MANAGE | Privilege::VIEW
    } else if privilege.contains(Privilege::VIEW) {
        Privilege::VIEW
    } else {
        Default::default()
    }
}

impl FromTLV<'_> for Privilege {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        match t.u32()? {
            1 => Ok(unfurl(Privilege::VIEW)),
            2 => {
                error!("ProxyView privilege not yet supporteds");
                Err(Error::Invalid)
            }
            3 => Ok(unfurl(Privilege::OPERATE)),
            4 => Ok(unfurl(Privilege::MANAGE)),
            5 => Ok(unfurl(Privilege::ADMIN)),
            _ => Err(Error::Invalid),
        }
    }
}

impl ToTLV for Privilege {
    fn to_tlv(
        &self,
        tw: &mut crate::tlv::TLVWriter,
        tag: crate::tlv::TagType,
    ) -> Result<(), Error> {
        let val = if self.contains(Privilege::ADMIN) {
            5
        } else if self.contains(Privilege::OPERATE) {
            4
        } else if self.contains(Privilege::MANAGE) {
            3
        } else if self.contains(Privilege::VIEW) {
            1
        } else {
            0
        };
        tw.u8(tag, val)
    }
}

#[derive(FromPrimitive, Copy, Clone)]
pub enum AuthMode {
    Pase = 1,
    Case = 2,
    Group = 3,
}

impl FromTLV<'_> for AuthMode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        num::FromPrimitive::from_u32(t.u32()?).ok_or(Error::Invalid)
    }
}

impl ToTLV for AuthMode {
    fn to_tlv(
        &self,
        tw: &mut crate::tlv::TLVWriter,
        tag: crate::tlv::TagType,
    ) -> Result<(), Error> {
        tw.u8(tag, *self as u8)
    }
}

#[derive(ToTLV)]
#[tlvargs(start = 1)]
pub struct AclEntry {
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: [Option<u64>; SUBJECTS_PER_ENTRY],
    targets: [Option<GenericPath>; TARGETS_PER_ENTRY],
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    #[tagval(0xFE)]
    fab_idx: u8,
}

impl AclEntry {
    pub fn new(fab_idx: u8, privilege: Privilege, auth_mode: AuthMode) -> Self {
        const INIT_SUBJECTS: Option<u64> = None;
        const INIT_TARGETS: Option<GenericPath> = None;
        let privilege = unfurl(privilege);
        Self {
            fab_idx,
            privilege,
            auth_mode,
            subjects: [INIT_SUBJECTS; SUBJECTS_PER_ENTRY],
            targets: [INIT_TARGETS; TARGETS_PER_ENTRY],
        }
    }

    pub fn add_subject(&mut self, subject: u64) -> Result<(), Error> {
        let index = self
            .subjects
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::NoSpace)?;
        self.subjects[index] = Some(subject);
        Ok(())
    }

    pub fn add_target(&mut self, target: GenericPath) -> Result<(), Error> {
        let index = self
            .targets
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::NoSpace)?;
        self.targets[index] = Some(target);
        Ok(())
    }
}

const MAX_ACL_ENTRIES: usize = ENTRIES_PER_FABRIC * fabric::MAX_SUPPORTED_FABRICS;
struct AclMgrInner {
    // Fabric 1's entry goes into 0th index
    entries: [Option<AclEntry>; MAX_ACL_ENTRIES],
}

pub struct AclMgr {
    inner: RwLock<AclMgrInner>,
}

impl AclMgr {
    pub fn new() -> Self {
        const INIT: Option<AclEntry> = None;
        Self {
            inner: RwLock::new(AclMgrInner {
                entries: [INIT; MAX_ACL_ENTRIES],
            }),
        }
    }

    pub fn add(&self, entry: AclEntry) -> Result<(), Error> {
        let mut inner = self.inner.write().unwrap();
        let cnt = inner
            .entries
            .iter()
            .flatten()
            .filter(|a| a.fab_idx == entry.fab_idx)
            .count();
        if cnt >= ENTRIES_PER_FABRIC {
            return Err(Error::NoSpace);
        }
        let index = inner
            .entries
            .iter()
            .position(|a| a.is_none())
            .ok_or(Error::NoSpace)?;
        inner.entries[index] = Some(entry);
        Ok(())
    }

    pub fn for_each_acl<T>(&self, mut f: T) -> Result<(), Error>
    where
        T: FnMut(&AclEntry),
    {
        let inner = self.inner.read().unwrap();
        for entry in &inner.entries {
            if let Some(entry) = entry {
                f(entry)
            }
        }
        Ok(())
    }
}
