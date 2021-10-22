use std::process;
use matter::sbox;
use matter::data_model;
use matter::data_model::Attribute;
use matter::data_model::Cluster;
use matter::data_model::AttrValue;
use matter::error::*;
use matter::transport;
use matter::im_demux::*;
use matter::tlv::*;
use matter::utils::WriteBuf;

use log::{info};

// Temporary fake data model
struct MyDataModel {
    a: u32,
}

impl MyDataModel {
    fn new() -> MyDataModel {
        MyDataModel{a: 12}
    }
}

impl HandleInteraction for MyDataModel {
    fn handle_invoke_cmd(&mut self, cmd_path_ib: &CmdPathIb, variable: TLVElement, mut resp_buf: WriteBuf) -> Result<(), Error> {
        info!("In Data Model's Invoke Commmand Handler");
        println!("Found cmd_path_ib: {:?} and variable: {}", cmd_path_ib, variable);
        let dummy_invoke_resp = [0x00, 0x09, 0x11, 0x39, 0x01, 0x00, 0x15, 0x36, 0x00, 0x15, 0x37, 0x00, 0x24, 0x00, 0x00, 0x24,
                                 0x02, 0x31, 0x24, 0x03, 0x02, 0x18, 0x36, 0x02, 0x04, 0x00, 0x04, 0x01, 0x04, 0x00, 0x18, 0x18,
                                 0x18, 0x18];
        resp_buf.copy_from_slice(&dummy_invoke_resp[..]).unwrap();
        Ok(())
    }
}

fn main() {
    env_logger::init();
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let mut data_model = MyDataModel::new();
    let mut interaction_model = InteractionModel::init(&mut data_model);
    let mut transport_mgr = transport::mgr::Mgr::new().unwrap();
    transport_mgr.register_protocol(&mut interaction_model).unwrap();
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

