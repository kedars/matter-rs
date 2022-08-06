use crate::error::Error;
use astro_dnssd::{DNSServiceBuilder, RegisteredDnsService};
use log::info;

#[allow(dead_code)]
pub struct SysMdnsService {
    s: RegisteredDnsService,
}

/// Publish a mDNS service
/// name - can be a service name (comma separate subtypes may follow)
/// regtype - registration type (e.g. _matter_.tcp etc)
/// port - the port
pub fn sys_publish_service(
    name: &str,
    regtype: &str,
    port: u16,
    txt_kvs: &[[&str; 2]],
) -> Result<SysMdnsService, Error> {
    let mut builder = DNSServiceBuilder::new(regtype, port).with_name(name);

    info!("mDNS Registration Type {}", regtype);
    for kvs in txt_kvs {
        info!("mDNS TXT key {} val {}", kvs[0], kvs[1]);
        builder = builder.with_key_value(kvs[0].to_string(), kvs[1].to_string());
    }
    let s = builder.register().map_err(|_| Error::MdnsError)?;
    Ok(SysMdnsService { s })
}
