use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use rs_matter::sbox;
use rs_matter::data_model;
use rs_matter::data_model::Attribute;
use rs_matter::data_model::Cluster;
use rs_matter::data_model::AttrValue;
use rs_matter::transport::session;
use rs_matter::transport::proto_msg;


fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let mut session_mgr = session::SessionMgr::init();
    let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    // Create a fake entry as hard-coded in the 'bypass mode' in chip-tool
    let i2r_key = [ 0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8, 0x1b, 0x33];
    session_mgr.add(0, i2r_key, i2r_key, test_addr.ip()).unwrap();
    println!("The sessions mgr: {:x?}", session_mgr);
    let test_session = session_mgr.get(0, test_addr.ip());
    println!("The session: {:x?}", test_session);
    
    let _parser = proto_msg::ProtoMsgParser::new(&mut session_mgr);
}

fn data_model_init() -> Result <Box<data_model::Accessory>, &'static str> {
    let val: AttrValue = AttrValue::Int8(12);
    let mut a = Box::new(data_model::Accessory::default());
    a.add_endpoint(3)?
        .add_cluster(Cluster::new(12)?)?
        .add_attribute(Attribute::new(1, val)?)?;

    Ok(a)
}

