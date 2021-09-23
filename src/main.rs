use std::process;
use rs_matter::sbox;
use rs_matter::data_model;
use rs_matter::data_model::Attribute;
use rs_matter::data_model::Cluster;
use rs_matter::data_model::AttrValue;
use rs_matter::transport::udp;

fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let packet = Packet { a: String::from("Hi") };
    let transport: udp::Udp<Packet> = udp::Udp::new(packet);
    transport.start_daemon();
}

struct Packet {
    a: String,
}

impl udp::ConsumeMsg for Packet {
    fn consume_message(&self, msg: &[u8], len: usize, src: std::net::SocketAddr) {
        println!("Received: len {}, src {}", len, src);
        println!("Data: {:x?}", &msg[0..len]);
    }
}

fn data_model_init() -> Result <Box<data_model::Accessory>, &'static str> {
    let val: AttrValue = AttrValue::Int8(12);
    let mut a = Box::new(data_model::Accessory::default());
    a.add_endpoint(3)?
        .add_cluster(Cluster::new(12)?)?
        .add_attribute(Attribute::new(1, val)?)?;

    Ok(a)
}
