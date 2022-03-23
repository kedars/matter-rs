use std::sync::{Arc, Mutex, Once};

use crate::error::Error;

use log::error;

pub struct Mdns {}

static mut G_MDNS: Option<Arc<Mutex<Mdns>>> = None;
static INIT: Once = Once::new();

#[allow(dead_code)]
pub struct MdnsService {}

impl Mdns {
    fn new() -> Self {
        Self {}
    }

    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_MDNS = Some(Arc::new(Mutex::new(Mdns::new())));
            });
            Ok(G_MDNS.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    pub fn publish_service(name: &str) -> Result<MdnsService, Error> {
        error!("Linux is not yet supported for MDNS Service");
        Ok(MdnsService {})
    }
}
