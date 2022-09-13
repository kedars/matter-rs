use crate::error::Error;
use std::vec::Vec;
use log::info;
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use libmdns::{Service, Responder};

#[allow(dead_code)]
pub struct SysMdnsService {
    service: Service,
}

lazy_static!{
    static ref RESPONDER: Arc<Mutex<Responder>> = Arc::new(Mutex::new(Responder::new().unwrap()));
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
    info!("mDNS Registration Type {}", regtype);
    info!("mDNS properties {:?}", txt_kvs);

    let mut properties = Vec::new();
    for kvs in txt_kvs {
        info!("mDNS TXT key {} val {}", kvs[0], kvs[1]);
        properties.push(format!("{}={}", kvs[0], kvs[1]));
    }
    let properties: Vec<&str> = properties.iter().map(|entry| entry.as_str()).collect();

    let responder = RESPONDER.lock().map_err(|_| Error::MdnsError)?;
    let service = responder.register(
        regtype.to_owned(),
        name.to_owned(),
        port,
        &properties,
    );

    Ok(SysMdnsService {service})
}
