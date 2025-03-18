use std::collections::HashSet;
use dashcore::hashes::hex::FromHex;
use dashcore::secp256k1::rand::random;
use dash_spv_crypto::crypto::data_ops::Data;
use dash_spv_crypto::util::address::address;
use dash_spv_crypto::util::data_append::DataAppend;
use dash_spv_crypto::util::script::ScriptElement;
use dash_spv_crypto::util::{base58, ScriptMap};

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
pub fn test_bits_are_true_operations() {
    let number1 =
        <[u8; 32]>::from_hex("0100000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    let number50 =
        <[u8; 32]>::from_hex("3200000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
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

const LEN: usize = 500;
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

// #[test]
// pub fn test_bitwise_ops() {
//     let a = 7u64;
//     let b = 5u64;
//     // UInt256()
//     let ab = a.to_le_bytes();
//     let bb = b.to_le_bytes();
//     // let tt = UInt256(ab);
//
//     let mut aa = [0u8; 32];
//     aa[0] = 7;
//     let mut bb = [0u8; 32];
//     bb[0] = 5;
//
//     let big_a = UInt256(aa);
//     let big_b = UInt256(bb);
//     println!("a: {} b: {}", big_a, big_b);
//     assert!(big_a > big_b, "A in uint 256 needs to be bigger than B");
//
//     let mut cc = [0u8; 32];
//     cc[8] = 1;
//     let big_c = UInt256(cc);
//     println!("c: {} a: {}", big_c, big_a);
//     // assert!(big_c > big_a, "C in uint 256 needs to be bigger than A");
//
//     let d: u64 = 1 << 30;
//
//     // uint64_t d = 1 << 30;
//     // UInt256 bigD = uint256_from_long(d);
//     // UInt256 bigDLeftShifted = uInt256ShiftLeftLE(bigD, 34);
//     // NSLog(@"%@ :: %@ :: %@ ", uint256_hex(bigC), uint256_hex(bigD), uint256_hex(bigDLeftShifted));
//     // XCTAssert(uint256_eq(bigC, bigDLeftShifted), @"C and D should be equal");
//     //
//     // uint32_t e = 1 << 30;
//     // UInt256 bigE = uint256_from_int(e);
//     // UInt256 bigELeftShifted = uInt256ShiftLeftLE(bigE, 34);
//     // XCTAssert(uint256_eq(bigELeftShifted, bigDLeftShifted), @"D and E should be equal");
// }

/// Equivalent to objc:
/// if ([txHashes intersectsOrderedSet:knownTxHashes]) {
///     [txHashes minusOrderedSet:knownTxHashes];
/// }
/// [knownTxHashes unionOrderedSet:txHashes];
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

pub fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// #[test]
// pub fn test_biguints_ops() {
//     let mut x = [0u8; 32];
//     x[0] = 0x32; // 50
//     let a = UInt256(x);
//     for i in 0..=32 {
//         println!("{}", a >> i);
//     }
//
//     let a = b"a0fcffffffffffffffffffffffffffffffffffffffffffffffffffffff4ffbff";
//     let b = b"100e000000000000000000000000000000000000000000000000000000000000";
//
// }

fn check_script_elements(data: &[u8], exp_script_elements: Vec<ScriptElement>) {
    assert_eq!(
        data.to_vec().script_elements(),
        exp_script_elements.clone(),
        "Script Elements don't match");
}

fn check_address_with_script_pubkey(data: &[u8], script_map: &ScriptMap, address: Option<String>) {
    let elem = data.to_vec().script_elements();
    let addr = address::with_script_pub_key(&data.to_vec(), script_map);
    assert_eq!(addr, address, "Address with script pubkey don't match")
}

fn check_address_with_script_signature(data: &[u8], script_map: &ScriptMap, address: Option<String>) {
    let elem = data.to_vec().script_elements();
    let addr = address::with_script_sig(&data.to_vec(), script_map);
    println!("check_address_with_script_signature: {:?} => {:?}", data.to_hex(), address);
    assert_eq!(addr, address, "Address with script signature don't match")
}

#[test]
fn test_script_elements() {
    // ScriptPubKey: None
    check_script_elements(b"\x6a", vec![ScriptElement::Number(106)]);
    check_script_elements(
        b"\x76\xa9\x14\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60\x88\xac",
        vec![
            ScriptElement::Number(118),
            ScriptElement::Number(169),
            ScriptElement::Data(b"\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60", 20),
            ScriptElement::Number(136),
            ScriptElement::Number(172)
        ]);
}

#[test]
fn test_address_with_script_pubkey() {
    check_address_with_script_pubkey(
        b"\x6a",
        &ScriptMap::TESTNET,
        None
    );

    check_address_with_script_pubkey(
        b"\x76\xa9\x14\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60\x88\xac",
        &ScriptMap::TESTNET,
        Some(base58::check_encode_slice(b"\x8c\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60"))
    );
    check_address_with_script_pubkey(
        Vec::from_hex("76a914351ddf96c5f0512584e1be4e77c73b96203a6b6088ac").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        Some(String::from("yRAJT1XYopJPLriAoS4rHA87GKd8gGW9rN"))
    );
    check_address_with_script_pubkey(
        Vec::from_hex("6a1414ec6c36e6c39a9181f3a261a08a5171425ac5e2").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        None
    );
    check_address_with_script_pubkey(
        Vec::from_hex("76a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288ac").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        Some(String::from("yNE5ayfLHEpunjKYJoD9oDNNfCcpeZtDf2"))
    );
    check_address_with_script_pubkey(
        Vec::from_hex("76a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        Some(String::from("yMWfjiYVs5X4pYpxrWG4tkrSA3mi5zUW8f"))
    );
}

#[test]
fn test_address_with_script_signature() {
    check_address_with_script_signature(
        b"\x01\x6a\x01\x01",
        &ScriptMap::TESTNET,
        Some("8xPfejPddAMauCGJZCSGjq33pQWi4uQtpR".to_string()));
    check_address_with_script_signature(
        Vec::from_hex("4730440220437f15af30180be323ca1a1e0c47de2a597abba2a57d4f76e2584ce7d3e8d40802202705342f334991c9eaa2757ea63c5bb305abf14a66a1ce727ef2689a92bcee55012103a65caff6ca4c0415a3ac182dfc2a6d3a4dceb98e8b831e71501df38aa156f2c1").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        Some("yNPbcFfabtNmmxKdGwhHomdYfVs6gikbPf".to_string()));
    check_address_with_script_signature(
        Vec::from_hex("47304402204972e37e8b7ae4aeb30388b79dfb6067fe6a2d3fd751e1031b924b857bfe483c02200c58de282b10dc536a161b34a606890779d552ba618738018ad1f21f669912540121038d18456ebe83c1650166a1d5145c9a9456b35f9258338b54d98257b968b765da").unwrap().as_slice(),
        &ScriptMap::TESTNET,
        Some("ya2XwWQUzfC7kvLUVsdPteaeCxfAS4yLEC".to_string()));

    check_address_with_script_signature(
        Vec::from_hex("a0a0a0a0a0a0a0a0a0a0").unwrap().as_slice(),
        &ScriptMap::MAINNET,
        None);
}
