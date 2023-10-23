use crate::bindings::common::{processor_create_cache, register_processor};
use crate::bindings::masternode::process_mnlistdiff_from_message;
use crate::chain::common::chain_type::ChainType;
use crate::crypto::byte_util::UInt256;
use crate::ffi::from::FromFFI;
use crate::hashes::hex::FromHex;
use crate::lib_tests::tests::{add_insight_lookup_default, assert_diff_result, get_block_hash_by_height_default, get_llmq_snapshot_by_block_hash_default, get_masternode_list_by_block_hash_default, get_merkle_root_by_hash_default, hash_destroy_default, masternode_list_destroy_default, masternode_list_save_default, message_from_file, save_llmq_snapshot_default, should_process_diff_with_range_default, snapshot_destroy_default, FFIContext, get_block_height_by_hash_from_context, get_cl_signature_by_block_hash_from_context, save_cl_signature_in_cache};
use crate::tests::block_store::init_testnet_store;

#[test]
fn test_mnl_saving_to_disk() {
    // testMNLSavingToDisk
    let chain = ChainType::TestNet;
    let bytes = message_from_file("ML_at_122088.dat");
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: init_testnet_store()
    });
    let processor = unsafe {
        register_processor(
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            get_cl_signature_by_block_hash_from_context,
            save_cl_signature_in_cache,
            get_masternode_list_by_block_hash_default,
            masternode_list_save_default,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
        )
    };
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        false,
        false,
        70221,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    println!("{:?}", result);
    assert_diff_result(context, result);
    let result = unsafe { &*result };
    let block_hash = UInt256(unsafe { *result.block_hash });
    let masternode_list = unsafe { &*result.masternode_list };
    let masternode_list_decoded = unsafe { masternode_list.decode() };
    assert_eq!(
        UInt256::from_hex("94d0af97187af3b9311c98b1cf40c9c9849df0af55dc63b097b80d4cf6c816c5")
            .unwrap(),
        masternode_list_decoded.masternode_merkle_root.unwrap(),
        "MNList merkle root should be valid"
    );
}
