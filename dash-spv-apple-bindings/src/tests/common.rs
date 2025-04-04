use std::{fs, io::Read};
use std::sync::Arc;
use dashcore::hashes::Hash;
use dashcore::hashes::hex::FromHex;
use dashcore::ProTxHash;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::logger::register_rust_logger;
use dash_spv_masternode_processor::block_store::MerkleBlock;
use dash_spv_masternode_processor::processing::processor::processing_error::ProcessingError;
use dash_spv_masternode_processor::test_helpers::load_message;
pub use dash_spv_masternode_processor::tests::FFIContext;
use crate::ffi_core_provider::FFICoreProvider;

extern crate libc;
extern crate reqwest;

#[cfg(all(feature = "test-helpers", feature = "use_serde"))]
pub fn get_block_from_insight_by_hash(hash: [u8; 32]) -> Option<MerkleBlock> {
    use dashcore::secp256k1::hashes::hex::DisplayHex;
    use dash_spv_crypto::crypto::byte_util::Reversed;
    let path = format!("https://testnet-insight.dashevo.org/insight-api/block/{}", hash.reversed().to_lower_hex_string().as_str());
    request_block(path)
}
#[cfg(all(feature = "test-helpers", feature = "use_serde"))]
pub fn get_block_from_insight_by_height(height: u32) -> Option<MerkleBlock> {
    let path = format!("https://testnet-insight.dashevo.org/insight-api/block/{}", height);
    request_block(path)
}

#[cfg(all(feature = "test-helpers", feature = "use_serde"))]
pub fn request_block(path: String) -> Option<MerkleBlock> {
    println!("request_block: {}", path.as_str());
    match reqwest::blocking::get(path.as_str()) {
        Ok(response) => match response.json::<serde_json::Value>() {
            Ok(json) => {
                let block: dash_spv_masternode_processor::tests::serde_helper::Block = serde_json::from_value(json).unwrap();
                let merkle_block = MerkleBlock::from(block);
                println!("request_block: {}", path.as_str());
                Some(merkle_block)
            },
            Err(err) => {
                println!("{}", err);
                None
            },
        },
        Err(err) => {
            println!("{}", err);
            None
        },
    }
}

pub fn register_logger() {
    unsafe { register_rust_logger(); }
}

pub fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    //println!("get_file_as_byte_vec: {}", filename);
    if let (Ok(mut f), Ok(metadata)) = (fs::File::open(&filename), fs::metadata(&filename)) {
        let mut buffer = vec![0; metadata.len() as usize];
        if let Ok(()) = f.read_exact(&mut buffer) {
            return buffer;
        }
    }
    panic!("get_file_as_byte_vec: error for: {}", filename)
}

pub fn perform_mnlist_diff_test_for_message(
    hex_string: &str,
    should_be_total_transactions: u32,
    verify_string_hashes: Vec<&str>,
    verify_string_smle_hashes: Vec<&str>,
    allow_invalid_merkle_roots: bool
) {
    let bytes = Vec::from_hex(hex_string).unwrap();
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let message: &[u8] = unsafe { std::slice::from_raw_parts(c_array, length) };
    let chain = ChainType::TestNet;
    let offset = &mut 0;
    assert!(length - *offset >= 32);
    let base_block_hash = TryInto::<[u8; 32]>::try_into(&message[..32]).expect("Error converting message");
    assert!(length - *offset >= 32);
    let _block_hash = TryInto::<[u8; 32]>::try_into(&message[32..64]).expect("Error converting message");
    assert!(length - *offset >= 4);

    let total_transactions = u32::from_le_bytes(message[64..68].try_into().expect("Error converting message"));
    assert_eq!(total_transactions, should_be_total_transactions, "Invalid transaction count");

    let use_insight_as_backup = false;
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain.clone(), false));
    let mut processor = FFICoreProvider::default_processor(context, chain);
    let (base_block_hash, block_hash) = processor.process_mn_list_diff_result_from_message(&bytes, None, true)
        .expect("Failed to process mnlistdiff");
    let masternode_list = processor.masternode_list_for_block_hash(block_hash.to_byte_array())
        .expect(format!("Masternode List at {}", block_hash.to_string()).as_str());

    let masternodes = &masternode_list.masternodes;
    let mut pro_tx_hashes: Vec<ProTxHash> = masternodes.keys().cloned().collect();
    // let mut pro_tx_hashes: Vec<[u8; 32]> = masternodes.keys().map(|hash| hash.to_byte_array()).collect();
    pro_tx_hashes.sort();
    let mut verify_hashes: Vec<ProTxHash> = verify_string_hashes
        .into_iter()
        .map(|h| ProTxHash::from_hex(h).unwrap())

            // <[u8; 32]>::from_hex(h).unwrap().reversed())
        .collect();
    verify_hashes.sort();

    pro_tx_hashes.iter().zip(verify_hashes.iter()).for_each(|(h1, h2)| {
        println!("{} == {}", h1.to_hex(), h2.to_hex());
    });

    assert_eq!(verify_hashes, pro_tx_hashes, "Provider transaction hashes");
    let mut masternode_list_hashes: Vec<[u8; 32]> = pro_tx_hashes
        .iter()
        .map(|hash| masternodes[hash].entry_hash.to_byte_array())
        .collect();
    masternode_list_hashes.sort();
    let mut verify_smle_hashes: Vec<[u8; 32]> = verify_string_smle_hashes
        .into_iter()
        // TODO: figure out why it now works without reversing
        .map(|h| <[u8; 32]>::from_hex(h).unwrap())
        .collect();
    verify_smle_hashes.sort();
    assert_eq!(masternode_list_hashes, verify_smle_hashes, "SMLE transaction hashes");
    // assert!(result.has_found_coinbase, "The coinbase was not part of provided hashes");
}

pub fn load_masternode_lists_for_files(
    files: Vec<String>,
    assert_validity: bool,
    context: Arc<FFIContext>,
    allow_invalid_merkle_roots: bool,
    chain_type: ChainType
) -> bool {
    let mut processor = FFICoreProvider::default_processor(Arc::clone(&context), chain_type.clone());
    for file in files {
        let bytes = load_message(chain_type.identifier(), file.as_str());
        match processor.process_mn_list_diff_result_from_message(&bytes, None, true) {
            Ok((base_block_hash, block_hash)) => {
                println!("List {}..{} successfully processed", base_block_hash.to_string(), block_hash.to_string())
            }
            Err(err) => {
                panic!("Should be valid result: {}", err);
            }
        }
    }
    true
}
pub fn extract_protocol_version_from_filename(filename: &str) -> Option<u32> {
    filename.split("__")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<u32>().ok())
}

pub fn assert_diff_chain(chain: ChainType, diff_files: &[&'static str], qrinfo_files: &[&'static str], block_store: Option<Vec<MerkleBlock>>, allow_invalid_merkle_roots: bool) {
    register_logger();
    let context = Arc::new(FFIContext::chain_default(chain.clone(), false, block_store.unwrap_or_default()));
    let mut processor = FFICoreProvider::default_processor(Arc::clone(&context), chain.clone());
    diff_files.iter().for_each(|filename| {
        let protocol_version = extract_protocol_version_from_filename(filename).unwrap_or(70219);
        let message = load_message(chain.identifier(), filename);
        // let result = processor.mn_list_diff_result_from_message(&message, true, protocol_version, allow_invalid_merkle_roots, null())
        //     .expect("Failed to process mnlistdiff");
        let maybe_result = processor.process_mn_list_diff_result_from_message(&message, None, true);
        match maybe_result {
            Ok(_) |
            Err(ProcessingError::MissingLists(..)) => {},
            Err(err) => panic!("Failed to process mnlistdiff: {err}")
        }
        // println!("Diff is ok at {}", result.block_hash);
        // assert_diff_result(&ctx, &result);
        // let mut cache = ctx.cache.write().unwrap();
        // cache.mn_lists.insert(result.block_hash, result.masternode_list);
    });
    // ctx.is_dip_0024 = true;
    qrinfo_files.iter().for_each(|filename| {
        let protocol_version = extract_protocol_version_from_filename(filename).unwrap_or(70219);
        let message = load_message(chain.identifier(), filename);
        let maybe_result = processor.process_qr_info_result_from_message(&message, false, true);
        match maybe_result {
            Ok(_) |
            Err(ProcessingError::MissingLists(..)) => {},
            Err(err) => panic!("Failed to process qrinfo: {err}")
        }
        // assert_qrinfo_result(&ctx, &result);
        // let mut cache = ctx.cache.write().unwrap();
        // if !result.result_at_h_4c.is_some() {
        //     let result = result.result_at_h_4c.unwrap();
        //     cache.mn_lists.insert(result.block_hash, result.masternode_list);
        // }
        // let result_at_h_3c = result.result_at_h_3c;
        // cache.mn_lists.insert(result_at_h_3c.block_hash, result_at_h_3c.masternode_list);
        // let result_at_h_2c = result.result_at_h_2c;
        // cache.mn_lists.insert(result_at_h_2c.block_hash, result_at_h_2c.masternode_list);
        // let result_at_h_c = result.result_at_h_c;
        // cache.mn_lists.insert(result_at_h_c.block_hash, result_at_h_c.masternode_list);
        // let result_at_h = result.result_at_h;
        // cache.mn_lists.insert(result_at_h.block_hash, result_at_h.masternode_list);
        // let result_at_tip = result.result_at_tip;
        // cache.mn_lists.insert(result_at_tip.block_hash, result_at_tip.masternode_list);
    });
}