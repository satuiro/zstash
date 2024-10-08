use std::fs::create_dir_all;

use anyhow::Context;
use clap::{Arg, Command};
// use color_eyre::eyre::{Ok, Result};

fn main() {
    // ensure that the directory for storage exists
    let secure_dir = zstash::get_secure_dir();
    let _ = create_dir_all(&secure_dir).with_context(|| "Could not create a secure directory");

    // println!("this is the main function");
    // create the command line interface using clap
    let matches = Command::new("zstash")
        .version("1.0")
        .author("Satuiro")
        .about("Rust based secure file storage and sharing system")
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt a file")
                .arg(Arg::new("file").required(true).index(1)),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a file")
                .arg(Arg::new("file").required(true).index(1)),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a file")
                .arg(Arg::new("file").required(true).index(1)),
        )
        .get_matches();

    // handle the matches for appropriate function
    match matches.subcommand() {
        Some(("encrypt", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            let _ = zstash::encrypt_file(file);
        }
        Some(("decrypt", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            let _ = zstash::decrypt_file(file);
        }
        Some(("delete", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            zstash::delete_file(file);
        }
        _ => eprintln!("Invalid command. Use --help for more information."),
    }
}
