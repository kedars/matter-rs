use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use crate::{
    data_model::objects::{Access, Privilege},
    error::Error,
    fabric,
    interaction_model::messages::GenericPath,
    sys::Psm,
    tlv::{FromTLV, TLVElement, TLVList, TLVWriter, TagType, ToTLV},
    utils::writebuf::WriteBuf,
};
use log::error;
use num_derive::FromPrimitive;

// Matter Minimum Requirements
pub const SUBJECTS_PER_ENTRY: usize = 4;
pub const TARGETS_PER_ENTRY: usize = 3;
pub const ENTRIES_PER_FABRIC: usize = 3;

// TODO: Check if this and the SessionMode can be combined into some generic data structure
#[derive(FromPrimitive, Copy, Clone, PartialEq, Debug)]
pub enum AuthMode {
    Pase = 1,
    Case = 2,
    Group = 3,
    Invalid = 4,
}

impl FromTLV<'_> for AuthMode {
    fn from_tlv(t: &TLVElement) -> Result<Self, Error>
    where
        Self: Sized,
    {
        num::FromPrimitive::from_u32(t.u32()?)
            .filter(|a| *a != AuthMode::Invalid)
            .ok_or(Error::Invalid)
    }
}

impl ToTLV for AuthMode {
    fn to_tlv(
        &self,
        tw: &mut crate::tlv::TLVWriter,
        tag: crate::tlv::TagType,
    ) -> Result<(), Error> {
        match self {
            AuthMode::Invalid => Ok(()),
            _ => tw.u8(tag, *self as u8),
        }
    }
}

pub struct Accessor {
    fab_idx: u8,
    // Could be node-id, NoC CAT, group id
    id: u64,
    auth_mode: AuthMode,
    // Is this the right place for this though, or should we just use a global-acl-handle-get
    acl_mgr: Arc<AclMgr>,
}

impl Accessor {
    pub fn new(fab_idx: u8, id: u64, auth_mode: AuthMode, acl_mgr: Arc<AclMgr>) -> Self {
        Self {
            fab_idx,
            id,
            auth_mode,
            acl_mgr,
        }
    }
}

#[derive(Debug)]
pub struct AccessDesc<'a> {
    // The object to be acted upon
    path: &'a GenericPath,
    target_perms: Option<Access>,
    // The operation being done
    // TODO: Currently this is Access, but we need a way to represent the 'invoke' somehow too
    operation: Access,
}

pub struct AccessReq<'a> {
    accessor: &'a Accessor,
    object: AccessDesc<'a>,
}

impl<'a> AccessReq<'a> {
    pub fn new(accessor: &'a Accessor, path: &'a GenericPath, operation: Access) -> Self {
        AccessReq {
            accessor,
            object: AccessDesc {
                path,
                target_perms: None,
                operation,
            },
        }
    }

    pub fn set_target_perms(&mut self, perms: Access) {
        self.object.target_perms = Some(perms);
    }

    pub fn allow(&self) -> bool {
        self.accessor.acl_mgr.allow(self)
    }
}

#[derive(FromTLV, ToTLV, Copy, Clone)]
pub struct Target {
    cluster: Option<u32>,
    endpoint: Option<u16>,
    device_type: Option<u32>,
}

type Subjects = [Option<u64>; SUBJECTS_PER_ENTRY];
type Targets = [Option<Target>; TARGETS_PER_ENTRY];
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
        const INIT_TARGETS: Option<Target> = None;
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

    pub fn add_target(&mut self, target: Target) -> Result<(), Error> {
        let index = self
            .targets
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::NoSpace)?;
        self.targets[index] = Some(target);
        Ok(())
    }

    fn match_accessor(&self, accessor: &Accessor) -> bool {
        if self.auth_mode != accessor.auth_mode {
            return false;
        }

        let mut allow = false;
        let mut entries_exist = false;
        for i in self.subjects.iter().flatten() {
            entries_exist = true;
            if accessor.id == *i {
                allow = true;
            }
        }
        if !entries_exist {
            // Subjects array empty implies allow for all subjects
            allow = true;
        }

        if allow && self.fab_idx == accessor.fab_idx {
            true
        } else {
            false
        }
    }

    fn match_access_desc(&self, object: &AccessDesc) -> bool {
        let mut allow = false;
        let mut entries_exist = false;
        for t in self.targets.iter().flatten() {
            entries_exist = true;
            if (t.endpoint.is_none() || t.endpoint == object.path.endpoint)
                && (t.cluster.is_none() || t.cluster == object.path.cluster)
            {
                allow = true
            }
        }
        if !entries_exist {
            // Targets array empty implies allow for all targets
            allow = true;
        }

        if allow {
            // Check that the object's access allows this operation with this privilege
            if let Some(access) = object.target_perms {
                access.is_ok(object.operation, self.privilege)
            } else {
                false
            }
        } else {
            false
        }
    }

    pub fn allow(&self, req: &AccessReq) -> bool {
        if self.match_accessor(req.accessor) && self.match_access_desc(&req.object) {
            true
        } else {
            false
        }
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
            if let Ok(inner) = AclMgrInner::load(&psm_lock) {
                inner
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

    pub fn allow(&self, req: &AccessReq) -> bool {
        // PASE Sessions have implicit access grant
        if req.accessor.auth_mode == AuthMode::Pase {
            return true;
        }
        let inner = self.inner.read().unwrap();
        for e in inner.entries.iter().flatten() {
            if e.allow(req) {
                return true;
            }
        }
        error!(
            "ACL Disallow for src id {} fab idx {}",
            req.accessor.id, req.accessor.fab_idx
        );
        false
    }
}
