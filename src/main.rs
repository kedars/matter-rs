use std::process;
use matter::core;
use matter::data_model::*;

fn main() {
    env_logger::init();

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

    let mut matter = core::Matter::new().unwrap();
    matter.start_daemon().unwrap();

}

fn data_model_init() -> Result <Box<Accessory>, &'static str> {
    let val: AttrValue = AttrValue::Int8(12);
    let mut a = Box::new(Accessory::default());
    a.add_endpoint(3)?
        .add_cluster(Cluster::new(12)?)?
        .add_attribute(Attribute::new(1, val)?)?;

    Ok(a)
}

