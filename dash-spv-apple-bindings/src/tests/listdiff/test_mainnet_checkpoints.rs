use dash_spv_masternode_processor::block_store::init_mainnet_store;
use dash_spv_masternode_processor::chain::common::ChainType;
use crate::common::register_processor;
use crate::masternode::process_mnlistdiff_from_message;
use crate::tests::common::{add_insight_lookup_default, FFIContext, get_block_hash_by_height_from_context, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_from_context, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, masternode_list_destroy_default, masternode_list_save_in_cache, save_llmq_snapshot_in_cache, should_process_diff_with_range_default, snapshot_destroy_default};

#[test]
fn test_mainnet_checkpoint_1720000() {
    /*{
        1720000,
        "000000000000001ef1f8a3d33bbe304c1d12f59f2c8aa989099dc215fd10903e",
        1660295895,
        0x19362176u,
        "ML1720000",
        "67c6348c35bc42aa4cabd25e29560f5d22c6a9fba274bf0c52fe73021d0e8d5e",
        "000000000000000000000000000000000000000000007715a9ae4dd7ff1d3902"
    }*/

    let chain = ChainType::MainNet;
    let context = &mut (FFIContext { chain, is_dip_0024: false, cache: &mut Default::default(), blocks: init_mainnet_store() });
    let bytes = chain.load_message("ML1720000.dat");
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
