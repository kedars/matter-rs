use std::sync::{Arc, Mutex, Once};

use crate::error::Error;
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};

pub struct Mdns {}

static mut G_MDNS: Option<Arc<Mutex<Mdns>>> = None;
static INIT: Once = Once::new();

#[allow(dead_code)]
pub struct MdnsService {
    s: RegisteredDnsService,
}

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
        let s = DNSServiceBuilder::new("_matter._tcp", 5540)
            .with_name(name)
            .register()
            .map_err(|_| Error::MdnsError)?;

        Ok(MdnsService { s })
    }
}
