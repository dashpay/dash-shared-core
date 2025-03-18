use std::{env, fs};
use std::io::Read;
use std::num::ParseIntError;
use dashcore::hashes::hex::FromHex;

pub fn load_message<T: ToString>(chain_id: T, filename: &str) -> Vec<u8> {
    let name = format!("{}/{}", chain_id.to_string(), filename);
    message_from_file(name.as_str())
}


pub fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    //println!("get_file_as_byte_vec: {}", filename);
    let mut f = fs::File::open(&filename).expect("no file found");
    let metadata = fs::metadata(&filename).expect("unable to read metadata");
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer).expect("buffer overflow");
    buffer
}
pub fn message_from_file(name: &str) -> Vec<u8> {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let filepath = format!("{}/files/{}", crate_dir, name);
    println!("{:?}", filepath);
    get_file_as_byte_vec(&filepath)
}





pub fn block_hash_to_block_hash(block_hash: String) -> [u8; 32] {
    <[u8; 32]>::from_hex(block_hash.as_str()).unwrap()
}

pub fn decode_hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn vec_to_arr<T, const N: usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

