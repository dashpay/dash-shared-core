use dashcore::secp256k1::rand::{Rng, thread_rng};
use dashcore::consensus::Encodable;
use dashcore::hashes::{sha256d, Hash};
use std::fmt::Write;

#[inline]
pub fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
    let mut rng = thread_rng();
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use dashcore::hashes::hex::FromHex;
    use dashcore::secp256k1::rand::random;
    use crate::crypto::data_ops::Data;
    const LEN: usize = 500;

    #[test]
    fn test_bitwise() {
        // Rust has own way...
        // objc equivalent for  UINT8_MAX >> (8 - signersOffset) << (8 - signersOffset);
        let test_values = vec![
            0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248,
            252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128,
            192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254,
            255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224,
            240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240, 248, 252, 254, 255, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 192, 224, 240,
            248, 252, 254, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let mut masks = vec![];
        for i in 0..416 {
            // Don't optimize
            #[allow(clippy::precedence)]
            let mask = 255 >> (((8 - i) % 32) + 32) % 32 << ((((8 - i) % 32) + 32) % 32);
            masks.push(mask);
        }
        assert_eq!(test_values.len(), masks.len(), "length not match");
        assert_eq!(test_values, masks, "bitwise hell");
    }


    #[test]
    pub fn test_bits_are_true_operations_random() {
        let mut data: [u8; LEN] = [0u8; LEN];
        for i in 0..32 {
            data[i] = random();
        }
        let vec = data.to_vec();
        (0..LEN).into_iter().for_each(|i| {
            println!("vec: {}", vec.bit_is_true_at_le_index(i as u32));
            println!("arr: {}", data.bit_is_true_at_le_index(i as u32));
        });

    }

    #[test]
    pub fn test_bits_are_true_operations() {
        let number50_shifted =
            <[u8; 32]>::from_hex("0000000000000000320000000000000000000000000000000000000000000000")
                .unwrap();
        let test_number50_shifted =
            <[u8; 32]>::from_hex("0000000000000000320000000000000000000000000000000000000000000000")
                .unwrap();
        let test_number =
            <[u8; 32]>::from_hex("0100000000000000320000000000000000000000000000000000000000000000")
                .unwrap();

        assert_eq!(
            number50_shifted, test_number50_shifted,
            "These numbers must be the same"
        );

        let data = test_number.as_slice();
        assert_eq!(data.true_bits_count(), 4, "Must be 6 bits here");
        assert!(data.bit_is_true_at_le_index(0), "This must be true");
        assert!(!data.bit_is_true_at_le_index(1), "This must be false");
        assert!(data.bit_is_true_at_le_index(65), "This must be true");
        assert!(!data.bit_is_true_at_le_index(67), "This must be false");
        assert!(data.bit_is_true_at_le_index(68), "This must be true");
    }

    #[test]
    pub fn collections_test() {
        let h0 = <[u8; 32]>::from_hex("02108f5f6f2743ce35ae58a94ab552381a17711ac54e9fd09358a0cb95beef79").unwrap();
        let h1 = <[u8; 32]>::from_hex("02108f5f6f2743ce35ae58a94ab552381a17711ac54e9fd09358a0cb95beef80").unwrap();
        let h2 = <[u8; 32]>::from_hex("74c41b22deefa3b3f1687f8cdaef64c69b84c2d172e872f408a4e3d86c5d929d").unwrap();
        let h3 = <[u8; 32]>::from_hex("74c41b22deefa3b3f1687f8cdaef64c69b84c2d172e872f408a4e3d86c5d929e").unwrap();
        let h4 = <[u8; 32]>::from_hex("74c41b22deefa3b3f1687f8cdaef64c69b84c2d172e872f408a4e3d86c5d929f").unwrap();
        let h5 = <[u8; 32]>::from_hex("84c41b22deefa3b3f1687f8cdaef64c69b84c2d172e872f408a4e3d86c5d929f").unwrap();
        let tx_hashes = HashSet::from([h0, h1, h5]);
        let known_tx_hashes = HashSet::from([h0, h1, h2, h3, h4]);
        let diff: HashSet<_> = tx_hashes.difference(&known_tx_hashes).collect();
        let union: HashSet<_>  = known_tx_hashes.union(&tx_hashes).collect();
        assert_eq!(diff, HashSet::from([&h5]));
        assert_eq!(union, HashSet::from([&h0, &h1, &h2, &h3, &h4, &h5]));
    }

}