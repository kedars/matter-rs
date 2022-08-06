use crate::error::Error;
use log::error;

#[allow(dead_code)]
pub struct SysMdnsService {}

pub fn sys_publish_service(
    _name: &str,
    _regtype: &str,
    _port: u16,
    _txt_kvs: &[[&str; 2]],
) -> Result<SysMdnsService, Error> {
    error!("Linux is not yet supported for MDNS Service");
    Ok(SysMdnsService {})
}
