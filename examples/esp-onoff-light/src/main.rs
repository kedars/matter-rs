mod dev_att;
use matter::core;
use matter::data_model::device_types::device_type_add_on_off_light;

use std::sync::Arc;

use esp_idf_sys::{self as _, EspError}; // If using the `binstart` feature of `esp-idf-sys`, always keep this module imported

use embedded_svc::wifi::{self, Configuration, Wifi};
use esp_idf_svc::{
    netif::EspNetifStack, nvs::EspDefaultNvs, sysloop::EspSysLoopStack, wifi::EspWifi,
};

use smol::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

fn main() {
    // Temporary. Will disappear once ESP-IDF 4.4 is released, but for now it is necessary to call this function once,
    // or else some patches to the runtime implemented by esp-idf-sys might not link properly.
    esp_idf_sys::link_patches();

    println!("Starting Wi-Fi!");
    let espwifi = start_wifi();
    println!("Wi-Fi started");
    env_logger::init();

        esp_idf_sys::esp!(unsafe {
            esp_idf_sys::esp_vfs_eventfd_register(&esp_idf_sys::esp_vfs_eventfd_config_t {
                max_fds: 5,
                ..Default::default()
            })
        }).unwrap();


//    let socketv4 = smol::block_on(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 5530)));
//let socketv6 = smol::block_on(UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 5530)));
//println!("Socketv4 and 6 {:?} {:?}", socketv4, socketv6);

    let dev_att = Box::new(dev_att::HardCodedDevAtt::new());


println!("here1");
    let mut matter = core::Matter::new(dev_att).unwrap();
println!("here2");
    let dm = matter.get_data_model();
    {
        let mut node = dm.node.write().unwrap();
println!("here3");
        let endpoint = device_type_add_on_off_light(&mut node).unwrap();
        println!("Added OnOff Light Device type at endpoint id: {}", endpoint);
        println!("Data Model now is: {}", node);
    }

println!("free memory: {}", unsafe {esp_idf_sys::esp_get_free_heap_size()});
    matter.start_daemon().unwrap();

}

fn start_wifi() -> Result<EspWifi, EspError> {
    let mut config = wifi::ClientConfiguration::default();
    config.ssid = "ssid".to_string();
    config.password = "password".to_string();

    let nw = Arc::new(EspNetifStack::new()?);
    let sys_loop = Arc::new(EspSysLoopStack::new()?);
    let nvs = Arc::new(EspDefaultNvs::new()?);

    let mut wifi = EspWifi::new(nw, sys_loop, nvs)?;
    wifi.set_configuration(&Configuration::Client(config))?;
    println!(" Wi-Fi status: {:?}", wifi.get_status());
    Ok(wifi)
}
