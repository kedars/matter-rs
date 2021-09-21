use std::process;
use rs_matter::sbox;
use rs_matter::data_model;

fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let a = data_model_init().unwrap_or_else(|err| {
        eprintln!("Error creating data model: {}", err);
        process::exit(1);
    });
    println!("Accessory: {:#?}", a);

}

fn data_model_init() -> Result <Box<data_model::Accessory>, &'static str> {
    let mut a = Box::new(data_model::Accessory::default());
    a.add_endpoint(3)?;
    a.add_cluster(1)?;
//    a.add_endpoint(4)?;
    Ok(a)
}
