use std::sync::{Arc, Mutex, Once};

use crate::{
    error::Error,
    sys::{sys_publish_service, SysMdnsService},
    transport::udp::MATTER_PORT,
};

#[derive(Default)]
/// The mDNS service handler
pub struct Mdns {
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Discriminator
    discriminator: u16,
}

static mut G_MDNS: Option<Arc<Mutex<Mdns>>> = None;
static INIT: Once = Once::new();

pub enum ServiceMode {
    Commissioned,
    Uncommissioned,
}

impl Mdns {
    fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    /// Get a handle to the globally unique mDNS instance
    pub fn get() -> Result<Arc<Mutex<Self>>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_MDNS = Some(Arc::new(Mutex::new(Mdns::new())));
            });
            Ok(G_MDNS.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    /// Set mDNS service specific values
    /// Values like vid, pid, discriminator etc
    // TODO: More things like device-type etc can be added here
    pub fn set_values(&mut self, vid: u16, pid: u16, discriminator: u16) {
        self.vid = vid;
        self.pid = pid;
        self.discriminator = discriminator;
    }

    /// Publish a mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    pub fn publish_service(name: &str, mode: ServiceMode) -> Result<SysMdnsService, Error> {
        match mode {
            ServiceMode::Commissioned => sys_publish_service(name, "_matter._tcp", MATTER_PORT),
            ServiceMode::Uncommissioned => sys_publish_service(name, "_matterc._udp", MATTER_PORT),
        }
    }
}
