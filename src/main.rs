use std::process;
use matter::sbox;
use matter::data_model;
use matter::data_model::Attribute;
use matter::data_model::Cluster;
use matter::data_model::AttrValue;
use matter::transport;

use log::{info};

fn main() {
    env_logger::init();
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let mut transport_mgr = transport::mgr::Mgr::new().unwrap();
    transport_mgr.start().unwrap();
}

fn data_model_init() -> Result <Box<data_model::Accessory>, &'static str> {
    let val: AttrValue = AttrValue::Int8(12);
    let mut a = Box::new(data_model::Accessory::default());
    a.add_endpoint(3)?
        .add_cluster(Cluster::new(12)?)?
        .add_attribute(Attribute::new(1, val)?)?;

    Ok(a)
}

