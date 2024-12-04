use std::{env, fs};
use std::io::Read;
use std::num::ParseIntError;
use dash_spv_crypto::crypto::{VarArray, VarBytes, byte_util::{BytesDecodable, UInt256}};
use crate::hashes::hex::FromHex;

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
    UInt256::from_hex(block_hash.as_str()).unwrap().0
}


// pub fn masternodes_to_masternodes(value: Vec<Masternode>) -> BTreeMap<UInt256, models::MasternodeEntry> {
//     let map: BTreeMap<UInt256, models::MasternodeEntry> = value
//         .into_iter()
//         .filter_map(|node| {
//
//
//             // #[serde(rename = "proTxHash")]
//             // pub pro_tx_hash: String,
//             // pub address: String,
//             // pub payee: String,
//             // pub status: String,
//             // pub pospenaltyscore: i64,
//             // pub lastpaidtime: i64,
//             // pub lastpaidblock: i64,
//             // pub owneraddress: String,
//             // pub votingaddress: String,
//             // pub collateraladdress: String,
//             // pub pubkeyoperator: String,
//
//
//             let provider_registration_transaction_hash = UInt256::from_hex(node.pro_tx_hash.as_str()).unwrap();
//             let confirmed_hash = UInt256::from_hex(node.confirmed_hash.as_str()).unwrap();
//             // node.service don't really need
//             let socket_address = SocketAddress { ip_address: Default::default(), port: 0 };
//             let voting_bytes = base58::from(node.votingaddress.as_str()).unwrap();
//             let key_id_voting = UInt160::from_bytes(&voting_bytes, &mut 0).unwrap();
//             let operator_public_key = UInt384::from_hex(node.pubkeyoperator.as_str()).unwrap();
//             let is_valid = node.status == "ENABLED";
//             let entry = models::MasternodeEntry::new(provider_registration_transaction_hash, confirmed_hash, socket_address, key_id_voting, operator_public_key, if is_valid { 1 } else { 0 });
//             // assert_eq!(message.len(), MN_ENTRY_PAYLOAD_LENGTH);
//             // entry.update_with_block_height(block_height);
//             Some(entry)
//         })
//         .fold(BTreeMap::new(), |mut acc, entry| {
//             let hash = entry
//                 .provider_registration_transaction_hash
//                 .clone()
//                 .reversed();
//             acc.insert(hash, entry);
//             acc
//         });
//     map
// }


pub fn parse_coinbase_tx_merkle_tree(bytes: &[u8]) -> (u32, VarArray<UInt256>, &[u8], usize) {
    let offset = &mut 0;
    let total_transactions = u32::from_bytes(bytes, offset).unwrap();
    let merkle_hashes = VarArray::<UInt256>::from_bytes(bytes, offset).unwrap();
    let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset).unwrap();
    (total_transactions, merkle_hashes, merkle_flags_var_bytes.1, merkle_flags_var_bytes.0.0 as usize)
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

