// use std::ffi::CString;
// use dash_spv_crypto::crypto::byte_util::{ConstDecodable, UInt256, UInt384};
// use dash_spv_crypto::derivation::{IIndexPath, IndexPath};
// use dash_spv_crypto::keys::KeyKind;
// // use dash_spv_crypto::keys::{key_bls_chaincode, key_bls_public_key, key_bls_with_bip32_seed_data, key_create_from_extended_public_key_data, key_extended_public_key_data, key_private_key_at_index_path, key_with_private_key};
// use dash_spv_crypto::network::ChainType;
// use dash_spv_masternode_processor::hashes::hex::{FromHex, ToHex};
// use crate::ffi::IndexPathData;
// use crate::types::opaque_key::OpaqueKey;

// #[test]
// fn test_keys() {
//     let key_type = KeyKind::ECDSA;
//     let extended_public_key_data_string = "3dc2e416b0f9fcfd74fe847ccd80f71cf961e7c4ddede29ce5e4b72a19ebccf2831ba2d803740b52e94ad4d526ff2b4340646b2ce1423545755b5825fabc741d1d74c155d7";
//     let extended_public_key_data = Vec::from_hex(extended_public_key_data_string).unwrap();
//
//     let extended_public_key = unsafe { key_create_from_extended_public_key_data(extended_public_key_data.as_ptr(), extended_public_key_data.len(), key_type) };
//     println!("extended_public_key: {:?}", extended_public_key);
//     let extended_public_key_data = unsafe { key_extended_public_key_data(extended_public_key) };
//     println!("extended_public_key_data: {:?}", extended_public_key_data);
//     let seed_bytes = unsafe { std::slice::from_raw_parts(extended_public_key_data.ptr, extended_public_key_data.len) };
//     println!("extended_public_key_data: {:?}", seed_bytes.to_hex());
//     assert_eq!(seed_bytes.to_hex(), extended_public_key_data_string);
// }

// #[test]
// fn derive_bls() {
//     let seed = Vec::from_hex("467c2dd58bbd29427fb3c5467eee339021a87b21309eeabfe9459d31eeb6eba9b2a1213c12a173118c84fd49e8b4bf9282272d67bf7b7b394b088eab53b438bc").unwrap();
//     let index_path = IndexPath::index_path_with_index(0u32);
//     let indexes = vec![
//         UInt256::from_hex("0900000000000000000000000000000000000000000000000000000000000000").unwrap(),
//         UInt256::from_hex("0500000000000000000000000000000000000000000000000000000000000000").unwrap(),
//         UInt256::from_hex("0500000000000000000000000000000000000000000000000000000000000000").unwrap(),
//         UInt256::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
//         UInt256::from_hex("0100000000000000000000000000000000000000000000000000000000000000").unwrap(),
//     ];
//     let hardened = vec![true, true, true, true, true];
//     let indexes = vec![0];
//     let index_path_data = IndexPathData  {
//         indexes: indexes.as_ptr(),
//         len: 1,
//     };
//     let indexes = b"09000000000000000000000000000000000000000000000000000000000000000500000000000000000000000000000000000000000000000000000000000000050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000";
//
//     unsafe {
//         let key = key_private_key_at_index_path(seed.as_ptr(), seed.len(), KeyKind::BLS, &index_path_data as *const IndexPathData, indexes.as_ptr(), hardened.as_ptr(), 5);
//         let ext_pub = key_extended_public_key_data(key);
//         println!("{:?}", ext_pub);
//     }
// }
//
