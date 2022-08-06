use std::sync::{Arc, Mutex, Once};

use crate::{
    error::Error,
    sys::{sys_publish_service, SysMdnsService},
    transport::udp::MATTER_PORT,
};

#[derive(Default)]
/// The mDNS service handler
pub struct MdnsInner {
    /// Vendor ID
    vid: u16,
    /// Product ID
    pid: u16,
    /// Discriminator
    discriminator: u16,
}

pub struct Mdns {
    inner: Mutex<MdnsInner>,
}

const SHORT_DISCRIMINATOR_MASK: u16 = 0x700;
const SHORT_DISCRIMINATOR_SHIFT: u16 = 8;

static mut G_MDNS: Option<Arc<Mdns>> = None;
static INIT: Once = Once::new();

pub enum ServiceMode {
    Commissioned,
    Commissionable,
}

impl Mdns {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MdnsInner {
                ..Default::default()
            }),
        }
    }

    /// Get a handle to the globally unique mDNS instance
    pub fn get() -> Result<Arc<Self>, Error> {
        unsafe {
            INIT.call_once(|| {
                G_MDNS = Some(Arc::new(Mdns::new()));
            });
            Ok(G_MDNS.as_ref().ok_or(Error::Invalid)?.clone())
        }
    }

    /// Set mDNS service specific values
    /// Values like vid, pid, discriminator etc
    // TODO: More things like device-type etc can be added here
    pub fn set_values(&self, vid: u16, pid: u16, discriminator: u16) {
        let mut inner = self.inner.lock().unwrap();
        inner.vid = vid;
        inner.pid = pid;
        inner.discriminator = discriminator;
    }

    /// Publish a mDNS service
    /// name - is the service name (comma separated subtypes may follow)
    /// mode - the current service mode
    pub fn publish_service(&self, name: &str, mode: ServiceMode) -> Result<SysMdnsService, Error> {
        match mode {
            ServiceMode::Commissioned => {
                sys_publish_service(name, "_matter._tcp", MATTER_PORT, &[])
            }
            ServiceMode::Commissionable => {
                let inner = self.inner.lock().unwrap();
                let short =
                    (inner.discriminator & SHORT_DISCRIMINATOR_MASK) >> SHORT_DISCRIMINATOR_SHIFT;
                let serv_type = format!("_matterc._udp,_S{},_L{}", short, inner.discriminator);

                let str_discriminator = format!("{}", inner.discriminator);
                let txt_kvs = [["D", &str_discriminator], ["CM", "1"]];
                sys_publish_service(name, &serv_type, MATTER_PORT, &txt_kvs)
            }
        }
    }
}
