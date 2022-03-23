use std::{
    convert::TryInto,
    fs::{DirBuilder, File},
    io::{Read, Write},
    sync::{Arc, Mutex, Once},
};

use crate::error::Error;

pub struct Psm {}

static mut G_PSM: Option<Arc<Mutex<Psm>>> = None;
static INIT: Once = Once::new();

const PSM_DIR: &str = "/tmp/boink_psm";

macro_rules! psm_path {
    ($key:ident) => {
        format!("{}/{}", PSM_DIR, $key)
    };
}

impl Psm {
    fn new() -> Result<Self, Error> {
        let result = DirBuilder::new().create(PSM_DIR);
        if let Err(e) = result {
            if e.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(e.into());
            }
        }

        Ok(Self {})
    }

    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_PSM = Some(Arc::new(Mutex::new(Psm::new().unwrap())));
            });
            Ok(G_PSM.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    pub fn set_kv_slice(&self, key: &str, val: &[u8]) -> Result<(), Error> {
        let mut f = File::create(psm_path!(key))?;
        f.write(val)?;
        Ok(())
    }

    pub fn get_kv_slice<'a>(&self, key: &str, val: &mut Vec<u8>) -> Result<usize, Error> {
        let mut f = File::open(psm_path!(key))?;
        let len = f.read_to_end(val)?;
        Ok(len)
    }

    pub fn set_kv_u64(&self, key: &str, val: u64) -> Result<(), Error> {
        let mut f = File::create(psm_path!(key))?;
        f.write(&val.to_be_bytes())?;
        Ok(())
    }

    pub fn get_kv_u64(&self, key: &str, val: &mut u64) -> Result<(), Error> {
        let mut f = File::open(psm_path!(key))?;
        let mut vec = Vec::new();
        let _ = f.read_to_end(&mut vec)?;
        *val = u64::from_be_bytes(vec.as_slice().try_into()?);
        Ok(())
    }
}
