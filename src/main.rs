extern crate crypto_hash;
extern crate ssb_legacy_msg_data;

use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::path::Path;

use crypto_hash::{digest, Algorithm::SHA256};
use ssb_legacy_msg_data::{
    to_weird_encoding,
    value::Value,
    json::{
        from_slice,
        to_vec
    }
};

fn main() {
    handle_nays(Path::new("test-data/syntax")).unwrap();
    handle_nays(Path::new("test-data/surrogate")).unwrap();
    handle_nays(Path::new("test-data/duplicate")).unwrap();
    handle_nays(Path::new("test-data/number")).unwrap();
    handle_yays(Path::new("test-data/yay")).unwrap();
}

fn handle_nays(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        if let Ok(v) = from_slice::<Value>(&contents) {
            println!("{:?}", path);
            println!("{:x?}", contents);
            println!("{:?}", String::from_utf8(contents.clone()));
            println!("{:?}", v);
            println!("{}", "Parsed invalid input");
            panic!("{:?}", v);
        }

        i += 1;
    }

    println!("handled {} files at {:?}", i, path);
    Ok(())
}

fn handle_yays(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        if let Some(_) = path.extension() {
            continue;
        }
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        match from_slice::<Value>(&contents) {
            Err(e) => {
                println!("{:?}", path);
                println!("{:?}", String::from_utf8(contents.clone()).unwrap());
                println!("{:x?}", contents);
                println!("{}", "Did not decode the input into a ValueOrdered");
                panic!("{:?}", e);
            }

            Ok(v) => {
                let enc = to_vec(&v, false).unwrap();
                let mut enc_path = path.clone();
                enc_path.set_extension("json_signing");
                let mut exp_enc = Vec::new();
                File::open(enc_path)?.read_to_end(&mut exp_enc)?;
                if enc != exp_enc {
                    // if from_slice::<Value>(&enc) == from_slice::<Value>(&exp_enc) {
                    //     continue;
                    // }
                    println!("{:?}", path);
                    println!("{:?}", String::from_utf8(contents.clone()).unwrap());
                    println!("{:x?}", contents);
                    println!("{}", "Wrong signing encoding");
                    println!("js: {}", String::from_utf8(exp_enc.clone()).unwrap());
                    println!("rs: {}", String::from_utf8(enc.clone()).unwrap());
                    println!("js: {:x?}", exp_enc.clone());
                    println!("rs: {:x?}", enc.clone());
                    assert!(false);
                }

                let (h, length) = weird_stuff(std::str::from_utf8(&enc).unwrap());

                let mut hash_path = path.clone();
                hash_path.set_extension("sha256");
                let mut exp_hash = Vec::new();
                File::open(hash_path)?.read_to_end(&mut exp_hash)?;
                if h != exp_hash {
                    println!("{:?}", path);
                    println!("{:?}", String::from_utf8(contents.clone()).unwrap());
                    println!("{:x?}", contents);
                    println!("{}", "Wrong hash");
                    println!("js: {:x?}", exp_hash);
                    println!("rs: {:x?}", h);
                    assert!(false);
                }

                let mut len_path = path.clone();
                len_path.set_extension("length");
                let mut exp_len = Vec::new();
                File::open(len_path)?.read_to_end(&mut exp_len)?;
                assert_eq!(length, usize::from_str_radix(std::str::from_utf8(&exp_len).unwrap(), 10).unwrap());

                i += 1;
            }
        }
    }

    println!("handled {} files at {:?}", i, path);

    Ok(())
}

// Computes a sha256 hash of the weird encoding, and also computes the length of the weird encoding.
fn weird_stuff(s: &str) -> (Vec<u8>, usize) {
    let weird_data = to_weird_encoding(s).collect::<Vec<u8>>();
    // println!("\noriginal: {:?}\nweird: {:?}\n", s.as_bytes(), weird_data);
    return (digest(SHA256, &weird_data[..]), weird_data.len());
}
