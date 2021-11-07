use std::process;
use matter::core;
use matter::data_model::*;
use matter::error::*;

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

fn data_model_init() -> Result <Box<Node>, Error> {
    let mut node = Node::new()?;
    node.add_endpoint(3)?;

    let mut test_cluster = Cluster::new(12)?;
    test_cluster.add_attribute(Attribute::new(1, AttrValue::Int8(2))?)?;

    node.add_cluster(test_cluster)?;

    Ok(node)
}

