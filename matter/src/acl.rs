use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use crate::{
    data_model::objects::Privilege,
    error::Error,
    fabric,
    interaction_model::messages::GenericPath,
    sys::Psm,
    tlv::{FromTLV, TLVElement, TLVList, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};
use num_derive::FromPrimitive;

// Matter Minimum Requirements
pub const SUBJECTS_PER_ENTRY: usize = 4;
pub const TARGETS_PER_ENTRY: usize = 3;
pub const ENTRIES_PER_FABRIC: usize = 3;

#[derive(FromPrimitive, Copy, Clone, PartialEq)]
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

type Subjects = [Option<u64>; SUBJECTS_PER_ENTRY];
type Targets = [Option<GenericPath>; TARGETS_PER_ENTRY];
#[derive(ToTLV, FromTLV, Copy, Clone)]
#[tlvargs(start = 1)]
pub struct AclEntry {
    privilege: Privilege,
    auth_mode: AuthMode,
    subjects: Subjects,
    targets: Targets,
    // TODO: Instead of the direct value, we should consider GlobalElements::FabricIndex
    #[tagval(0xFE)]
    fab_idx: u8,
}

impl AclEntry {
    pub fn new(fab_idx: u8, privilege: Privilege, auth_mode: AuthMode) -> Self {
        const INIT_SUBJECTS: Option<u64> = None;
        const INIT_TARGETS: Option<GenericPath> = None;
        let privilege = privilege;
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
type AclEntries = [Option<AclEntry>; MAX_ACL_ENTRIES];

#[derive(ToTLV, FromTLV)]
struct AclMgrInner {
    entries: AclEntries,
}

const ACL_KV_ENTRY: &str = "acl";
const ACL_KV_MAX_SIZE: usize = 300;
impl AclMgrInner {
    pub fn store(&self, psm: &MutexGuard<Psm>) -> Result<(), Error> {
        let mut acl_tlvs = [0u8; ACL_KV_MAX_SIZE];
        let mut wb = WriteBuf::new(&mut acl_tlvs, ACL_KV_MAX_SIZE);
        let mut tw = TLVWriter::new(&mut wb);
        self.entries.to_tlv(&mut tw, TagType::Anonymous)?;
        psm.set_kv_slice(ACL_KV_ENTRY, wb.as_slice())
    }

    pub fn load(psm: &MutexGuard<Psm>) -> Result<Self, Error> {
        let mut acl_tlvs = Vec::new();
        psm.get_kv_slice(ACL_KV_ENTRY, &mut acl_tlvs)?;
        let root = TLVList::new(&acl_tlvs)
            .iter()
            .next()
            .ok_or(Error::Invalid)?;

        Ok(Self {
            entries: AclEntries::from_tlv(&root)?,
        })
    }
}

pub struct AclMgr {
    inner: RwLock<AclMgrInner>,
    psm: Arc<Mutex<Psm>>,
}

impl AclMgr {
    pub fn new() -> Result<Self, Error> {
        let psm = Psm::get()?;
        let inner = {
            let psm_lock = psm.lock().unwrap();
            if let Ok(i) = AclMgrInner::load(&psm_lock) {
                i
            } else {
                const INIT: Option<AclEntry> = None;
                AclMgrInner {
                    entries: [INIT; MAX_ACL_ENTRIES],
                }
            }
        };
        Ok(Self {
            inner: RwLock::new(inner),
            psm,
        })
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

        let psm = self.psm.lock().unwrap();
        inner.store(&psm)
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
