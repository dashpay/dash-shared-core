use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::block_store::init_testnet_store;
use crate::common::register_processor;
use crate::masternode::process_mnlistdiff_from_message;
use crate::tests::common::{add_insight_lookup_default, assert_diff_result, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, masternode_list_destroy_default, masternode_list_save_in_cache, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, snapshot_destroy_default};

#[test]
fn test_checkpoint_530000() {
    let chain = ChainType::TestNet;
    let context = &mut (FFIContext { chain, is_dip_0024: false, cache: &mut Default::default(), blocks: init_testnet_store() });
    let bytes = chain.load_message("MNT530000.dat");
    let processor = unsafe {
        &mut *register_processor(
            chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_from_context,
            get_llmq_snapshot_by_block_hash_from_context,
            save_llmq_snapshot_in_cache,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            context as *mut _ as *mut std::ffi::c_void
        )
    };
    let result = unsafe {
        &*process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            chain,
            false,
            true,
            70221,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )
    };

    assert!(result.is_valid(), "Result must be valid");
}

// Need fix from core team
// #[test]
fn test_checkpoint_530000_70227() {
    let chain = ChainType::TestNet;
    let context = &mut (FFIContext { chain, is_dip_0024: false, cache: &mut Default::default(), blocks: init_testnet_store() });
    let bytes = chain.load_message("MNT_0_530000.dat");
    let processor = unsafe {
        &mut *register_processor(
            chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_from_context,
            get_llmq_snapshot_by_block_hash_from_context,
            save_llmq_snapshot_in_cache,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            context as *mut _ as *mut std::ffi::c_void
        )
    };
    let result = unsafe {
        &*process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            chain,
            false,
            true,
            70227,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )
    };
    assert_diff_result(context, result);
    // assert!(result.is_valid(), "Result must be valid");
}

