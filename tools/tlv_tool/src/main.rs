extern crate clap;
use clap::{App, Arg};
use simple_logger::SimpleLogger;
use matter::cert;
use matter::tlv;
use std::process;
use std::u8;

fn main() {
    SimpleLogger::new()
        .with_level(log::LevelFilter::Trace)
        .with_colors(true)
        .without_timestamps()
        .init()
        .unwrap();

    let m = App::new("tlv_tool")
        .arg(
            Arg::with_name("hex")
                .short("h")
                .long("hex")
                .help("The input is in Hexadecimal (Default)"),
        )
        .arg(
            Arg::with_name("dec")
                .short("d")
                .long("dec")
                .help("The input is in Decimal"),
        )
        .arg(
            Arg::with_name("cert")
                .long("cert")
                .help("The input is a Matter-encoded Certificate"),
        )
        .arg(Arg::with_name("tlvs").help("List of TLVs").required(true))
        .get_matches();

    // Assume hexadecimal by-default
    let base = if m.is_present("hex") {
        16
    } else if m.is_present("dec") {
        10
    } else {
        16
    };

    let list = m.value_of("tlvs").unwrap().split(' ');
    let mut tlv_list: [u8; 1024] = [0; 1024];
    let mut index = 0;
    for byte in list {
        let byte = byte.strip_prefix("0x").unwrap_or(byte);
        let byte = byte.strip_suffix(",").unwrap_or(byte);
        if let Ok(b) = u8::from_str_radix(byte, base) {
            tlv_list[index] = b;
            index += 1;
        } else {
            eprintln!("Error parsing input byte: {}", byte);
            process::exit(1);
        }
        if index >= 1024 {
            eprintln!("Input too long");
            process::exit(1);
        }
    }

//    println!("Decoding: {:x?}", &tlv_list[..index]);
    if m.is_present("cert") {
	let cert = cert::Cert::new(&tlv_list[..index]);
	println!("{}", cert);
    } else {
        tlv::print_tlv_list(&tlv_list[..index]);
    }
}
