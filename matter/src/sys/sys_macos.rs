use crate::error::Error;
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};

#[allow(dead_code)]
pub struct SysMdnsService {
    s: RegisteredDnsService,
}

/// Publish a mDNS service
/// name - can be a service name (comma separate subtypes may follow)
/// regtype - registration type (e.g. _matter_.tcp etc)
/// port - the port
pub fn sys_publish_service(name: &str, regtype: &str, port: u16) -> Result<SysMdnsService, Error> {
    let s = DNSServiceBuilder::new(regtype, port)
        .with_name(name)
        .register()
        .map_err(|_| Error::MdnsError)?;

    Ok(SysMdnsService { s })
}
