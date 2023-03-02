use serde::Serialize;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::fs::File;

use rpassword::read_password;
pub fn file_writer<T: Serialize, U: AsRef<Path>>(data: T, path: U) {
    let f = File::create(path).unwrap();
    let mut bfw = BufWriter::new(f);

    let raw_data = bincode::serialize(&data).unwrap();
    bfw.write(&raw_data).unwrap();
}

pub fn get_password(needs_twice: bool) -> String {
    print!("password -> ");
    std::io::stdout().flush().unwrap();
    let mut pass = read_password().unwrap();
    if needs_twice {
        loop {
            print!("reenter password ->");
            std::io::stdout().flush().unwrap();
            let repass = read_password().unwrap();
            if repass == pass {
                break;
            }
            eprintln!("password does not match");
            std::io::stderr().flush().unwrap();
            print!("password -> ");
            std::io::stdout().flush().unwrap();
            pass = read_password().unwrap();            
        }
    }

    pass
}