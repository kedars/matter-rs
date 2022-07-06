use std::sync::RwLock;

use crate::{error::Error, fabric, interaction_model::messages::GenericPath};

use bitflags::bitflags;

// Matter Minimum Requirements
pub const SUBJECTS_PER_ENTRY: usize = 4;
pub const TARGETS_PER_ENTRY: usize = 3;
pub const ENTRIES_PER_FABRIC: usize = 3;

bitflags! {
    pub struct Privilege: u8 {
        const VIEW = 0x01;
        const OPERATE = 0x02;
        const MANAGE = 0x04;
        const ADMIN = 0x08;
    }
}

pub enum AuthMode {
    Case,
    Group,
}

pub struct AclEntry {
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: [Option<u64>; SUBJECTS_PER_ENTRY],
    targets: [Option<GenericPath>; TARGETS_PER_ENTRY],
}

impl AclEntry {
    pub fn new(privilege: Privilege, auth_mode: AuthMode) -> Self {
        const INIT_SUBJECTS: Option<u64> = None;
        const INIT_TARGETS: Option<GenericPath> = None;
        Self {
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

struct AclMgrInner {
    // Fabric 1's entry goes into 0th index
    entries: [[Option<AclEntry>; ENTRIES_PER_FABRIC]; fabric::MAX_SUPPORTED_FABRICS],
}

pub struct AclMgr {
    inner: RwLock<AclMgrInner>,
}

impl AclMgr {
    pub fn new() -> Self {
        const INIT_ELEMENT: Option<AclEntry> = None;
        const INIT_ARRAY: [Option<AclEntry>; ENTRIES_PER_FABRIC] =
            [INIT_ELEMENT; ENTRIES_PER_FABRIC];
        Self {
            inner: RwLock::new(AclMgrInner {
                entries: [INIT_ARRAY; fabric::MAX_SUPPORTED_FABRICS],
            }),
        }
    }

    pub fn add(&self, fbr_idx: usize, entry: AclEntry) -> Result<(), Error> {
        let mut inner = self.inner.write().unwrap();
        let index = inner.entries[fbr_idx]
            .iter()
            .position(|a| a.is_none())
            .ok_or(Error::NoSpace)?;
        inner.entries[fbr_idx][index] = Some(entry);
        Ok(())
    }
}
