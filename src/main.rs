use std::mem;
use rs_matter::sbox;
use rs_matter::data_model;

fn main() {
    let x = sbox::sbox_new("Hello How are you").unwrap();
    println!("Hello, world!: {}", x);

    let mut a = data_model::Accessory::default();
    a.add_endpoint(3).unwrap();
//    a.add_endpoint(4).unwrap();
    println!("Accessory: {:#?}", a);

    let b: Box<u32>;
    println!("Sizeof: {}", mem::size_of::<Option<Box<u32>>>());
}


