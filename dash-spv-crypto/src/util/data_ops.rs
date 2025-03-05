use secp256k1::rand;
use secp256k1::rand::Rng;
use std::fmt::Write;
use dashcore::consensus::Encodable;
use hashes::sha256d;

#[inline]
pub fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size).map(|_| rng.gen_range(0..=255)).collect()
}


pub fn hex_with_data(data: &[u8]) -> String {
    let n = data.len();
    let mut s = String::with_capacity(2 * n);
    let iter = data.iter();
    for a in iter {
        write!(s, "{:02x}", a).unwrap();
    }
    s
}


pub fn short_hex_string_from(data: &[u8]) -> String {
    let hex_data = hex_with_data(data);
    if hex_data.len() > 7 {
        hex_data[..7].to_string()
    } else {
        hex_data
    }
}

#[inline]
pub fn merkle_root_from_hashes(hashes: Vec<[u8; 32]>) -> Option<[u8; 32]> {
    let length = hashes.len();
    let mut level = hashes;
    match length {
        0 => None,
        _ => {
            while level.len() != 1 {
                let len = level.len();
                let mut higher_level = Vec::<[u8; 32]>::with_capacity((0.5 * len as f64).ceil() as usize);
                for pair in level.chunks(2) {
                    let mut buffer = Vec::with_capacity(64);
                    pair[0].consensus_encode(&mut buffer).unwrap();
                    (pair.get(1).unwrap_or(&pair[0])).consensus_encode(&mut buffer).unwrap();
                    higher_level.push(sha256d::Hash::hash(buffer.as_ref()).to_byte_array());
                }
                level = higher_level;
            }
            Some(level[0])
        }
    }
}
