mod crypto;
mod uitl;

use std::path::PathBuf;
use std::io::{BufWriter, Write};

use crypto::{decrypt, encrypt};
use uitl::{file_writer, get_password};
use std::fs::File;

use clap::Parser;

#[derive(Debug, Parser)]
struct  Args { 
    #[arg(short, long, help = "暗号化")]
    encrypt: bool,
    #[arg(short, long, help = "復号化")]
    decrypt: bool,

    #[arg(help = "暗号化/復号化するファイルのパス")]
    target_file: String,

    #[arg(short = 'o', help = "出力のファイル名")]
    out_file: Option<String>
}

fn main() {
    let args = Args::parse();

    let target_file = PathBuf::from(&args.target_file);
    
    if args.decrypt == args.encrypt {
        panic!("-e -d のどちらか一方を指定してください")
    }


    if args.encrypt {
        let path = format!("{}.enc", args.target_file);
        let mut out_path = PathBuf::from(path);
        if let Some(path) = args.out_file {
            out_path = PathBuf::from(path);
        }

        let raw_password  = get_password(true);
        let enc_data = encrypt(&target_file, &raw_password);

        let f = File::create(out_path).unwrap();
        let mut bfw = BufWriter::new(f);
    
        let raw_data = bincode::serialize(&enc_data).unwrap();
        bfw.write(&raw_data).unwrap();

    } else if args.decrypt {
        let raw_password = get_password(false);
        let plain_data = decrypt(&target_file, &raw_password);
        let mut out_path = PathBuf::from(&plain_data.file_name);
        if let Some(path) = args.out_file {
            out_path = PathBuf::from(path);
        }
        
        file_writer(&plain_data.data, &out_path);
        let f = File::create(out_path).unwrap();
        let mut bfw = BufWriter::new(f);
    
        bfw.write(&plain_data.data).unwrap();
    }
}
