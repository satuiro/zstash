use clap::{Arg, Command};
// use color_eyre::eyre::{Ok, Result};

fn main() {
    let matches = Command::new("zstash")
        .version("1.0")
        .author("Satuiro")
        .about("Rust based secure file storage and sharing system")
        .subcommand(
            Command::new("encrypt")
            .about("Encrypt a file")
            .arg(Arg::new("file")
            .required(true)
            .index(1))
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a file")
                .arg(Arg::new("file")
                    .required(true)
                    .index(1)),
        )
        .subcommand(
            Command::new("delete")
                .about("Delete a file")
                .arg(Arg::new("file")
                    .required(true)
                    .index(1)),
        )
        .subcommand(
            Command::new("set-password")
                .about("Create a new password for authentication")
                .arg(Arg::new("password")
                    .required(true)
                    .index(1)),
        )
        .get_matches();

    // handle the matches for appropriate function 
    match matches.subcommand() {
        Some(("encrypt", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            let _ = zstash::encrypt_file(file);
        },
        Some(("decrypt", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            let _ = zstash::decrypt_file(file);
        },
        Some(("delete", sub_m)) => {
            let file = sub_m.get_one::<String>("file").expect("required argument");
            zstash::delete_file(file);
        },
        Some(("set-password", sub_m)) => {
            let password = sub_m.get_one::<String>("password").expect("required argument");
            let _ = zstash::set_password(&password);
        },
        _ => eprintln!("Invalid command. Use --help for more information."),
    }

}