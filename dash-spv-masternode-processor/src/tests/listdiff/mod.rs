use std::ptr::null_mut;
use hashes::hex::FromHex;
use dash_spv_crypto::crypto::byte_util::{BytesDecodable, Reversable};
use dash_spv_crypto::crypto::UInt256;
use dash_spv_crypto::network::ChainType;
use crate::processing::{CoreProvider, MasternodeProcessor};
use crate::tests::FFIContext;

pub mod llmq_snapshot;
pub mod testnet_core19;


pub fn perform_mnlist_diff_test_for_message_with_provider<T>(
    hex_string: &str,
    should_be_total_transactions: u32,
    verify_string_hashes: Vec<&str>,
    verify_string_smle_hashes: Vec<&str>,
    provider: T,
) where T: CoreProvider {
    let bytes = Vec::from_hex(hex_string).unwrap();
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let message: &[u8] = unsafe { std::slice::from_raw_parts(c_array, length) };
    let chain = ChainType::TestNet;
    let offset = &mut 0;
    assert!(length - *offset >= 32);
    let base_block_hash = UInt256::from_bytes(message, offset).unwrap();
    assert_ne!(base_block_hash, UInt256::default(), "Base block hash should NOT be empty here");
    assert!(length - *offset >= 32);
    let _block_hash = UInt256::from_bytes(message, offset).unwrap();
    assert!(length - *offset >= 4);
    let total_transactions = u32::from_bytes(message, offset).unwrap();
    assert_eq!(total_transactions, should_be_total_transactions, "Invalid transaction count");
    let use_insight_as_backup = false;

    let processor = MasternodeProcessor::new(provider.into());
    // let processor = register_default_processor(&mut context);

    let base_masternode_list_hash: *const u8 = null_mut();
    let mut context = FFIContext::create_default_context_and_cache(chain, false);

    // chain_type: ChainType,
    // use_insight_as_backup: bool,
    // is_from_snapshot: bool,
    // protocol_version: u32,

    let result = processor.mn_list_diff_result_from_message(&bytes, true, 70221, &mut context.cache)
        .expect("Failed to process mnlistdiff");
    let masternode_list = result.masternode_list;
    let masternodes = masternode_list.masternodes;
    // let masternodes = result.expect("Failed to process mnlistdiff").masternode_list.masternodes;

    // let processor = register_default_processor(&mut context);
    // let result = unsafe { &*process_mnlistdiff_from_message(
    //     c_array,
    //     length,
    //     chain,
    //     use_insight_as_backup,
    //     true,
    //     70221,
    //     processor,
    //     context.cache,
    //     &mut context as *mut _ as *mut std::ffi::c_void,
    // )};
    println!("result: {:?}", result);
    // let masternode_list = unsafe { (*result.masternode_list).decode() };
    let mut pro_tx_hashes: Vec<UInt256> = masternodes.clone().into_keys().collect();
    pro_tx_hashes.sort();
    let mut verify_hashes: Vec<UInt256> = verify_string_hashes
        .into_iter()
        .map(|h| UInt256::from_hex(h).unwrap().reverse())
        .collect();
    verify_hashes.sort();
    assert_eq!(verify_hashes, pro_tx_hashes, "Provider transaction hashes");
    let mut masternode_list_hashes: Vec<UInt256> = pro_tx_hashes
        .clone()
        .iter()
        .map(|hash| masternodes[hash].entry_hash)
        .collect();
    masternode_list_hashes.sort();
    let mut verify_smle_hashes: Vec<UInt256> = verify_string_smle_hashes
        .into_iter()
        // TODO: figure out why it now works without reversing
        // .map(|h| UInt256::from_hex(h).unwrap().reverse())
        .map(|h| UInt256::from_hex(h).unwrap())
        .collect();
    verify_smle_hashes.sort();
    assert_eq!(masternode_list_hashes, verify_smle_hashes, "SMLE transaction hashes");
    assert!(result.has_found_coinbase, "The coinbase was not part of provided hashes");
}

pub fn perform_mnlist_diff_test_for_message(
    hex_string: &str,
    should_be_total_transactions: u32,
    verify_string_hashes: Vec<&str>,
    verify_string_smle_hashes: Vec<&str>,
) {
}