use std::process;
use rs_matter::sbox;
use rs_matter::data_model;
use rs_matter::data_model::Attribute;
use rs_matter::data_model::Cluster;
use rs_matter::data_model::AttrValue;
use rs_matter::transport::udp;
use rs_matter::transport::packet::PacketParser;

fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let parser = PacketParser::new();
    let mut transport: udp::UdpListener<PacketParser> = udp::UdpListener::new(parser);
    transport.start_daemon().unwrap();
}

fn data_model_init() -> Result <Box<data_model::Accessory>, &'static str> {
    let val: AttrValue = AttrValue::Int8(12);
    let mut a = Box::new(data_model::Accessory::default());
    a.add_endpoint(3)?
        .add_cluster(Cluster::new(12)?)?
        .add_attribute(Attribute::new(1, val)?)?;

    Ok(a)
}
