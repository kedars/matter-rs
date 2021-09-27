use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process;
use rs_matter::sbox;
use rs_matter::data_model;
use rs_matter::data_model::Attribute;
use rs_matter::data_model::Cluster;
use rs_matter::data_model::AttrValue;
use rs_matter::transport::udp;
use rs_matter::transport::packet::PacketParser;
use rs_matter::transport::session;

use ccm::{Ccm, consts::{U16, U12}};
use ccm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
use aes::Aes128;


fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    test_aead();

    let mut session_mgr = session::SessionMgr::init();
    let test_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    // Create a fake entry as hard-coded in the 'bypass mode' in chip-tool
    let i2r_key = [ 0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8, 0x1b, 0x33];
    session_mgr.add(0, i2r_key, i2r_key, test_addr).unwrap();
    println!("The sessions mgr: {:x?}", session_mgr);
    let test_session = session_mgr.get(0, test_addr);
    println!("The session: {:x?}", test_session);
    
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

fn test_aead() {
    // Values as taken from Chip-Tool 'bypass' mode by instrumenting the parameters received for AES_CCM_Encrypt
    let key = [ 0x44, 0xd4, 0x3c, 0x91, 0xd2, 0x27, 0xf3, 0xba, 0x08, 0x24, 0xc5, 0xd8, 0x7c, 0xb8, 0x1b, 0x33];
    let iv = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let aad = [0x00, 0x11, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
    let mut cipher_text = [0xea, 0x9b, 0x85, 0xc6, 0x29, 0x1b, 0x19, 0xbd, 0x73, 0x31, 0x80, 0x30, 0x0b, 0x2d, 0x50, 0x8c, 0xe1, 0x6b, 0x71, 0x6f, 0xe3, 0xdd, 0xf8, 0xb6, 0x15, 0xcd, 0x28, 0xd3];
    let tag = [0xc1, 0x28, 0x22, 0x5e, 0x9a, 0x82, 0x29, 0xf2, 0x34, 0x84, 0xd9, 0x38, 0xdf, 0xcd, 0xf9, 0x56];

    // Matter Spec says Nonce size is 13, but the code has 12
    type AesCcm = Ccm<Aes128, U16, U12>;
    let cipher = AesCcm::new(GenericArray::from_slice(&key));
    let nonce = GenericArray::from_slice(&iv);
    let tag = GenericArray::from_slice(&tag);
    cipher.decrypt_in_place_detached(nonce, &aad, &mut cipher_text, &tag).unwrap_or_else(|err| {
        println!("Error in decryption");
    });

    println!("The decrypted vector is: {:0x?}", cipher_text);
}
