use std::collections::BTreeMap;
use dash_spv_masternode_processor::block_store::init_mainnet_store;
use dash_spv_masternode_processor::chain::common::chain_type::ChainType;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::models;
use crate::common::{processor_create_cache, register_processor};
use crate::masternode::process_mnlistdiff_from_message;
use crate::tests::common::{add_insight_lookup_default, assert_diff_result, FFIContext, get_block_hash_by_height_default, get_block_height_by_hash_from_context, get_llmq_snapshot_by_block_hash_default, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, masternode_list_destroy_default, masternode_list_save_in_cache, save_llmq_snapshot_default, should_process_diff_with_range_default, snapshot_destroy_default};

#[test]
fn test_mainnet_reload_with_processor() {
    let chain = ChainType::MainNet;
    let files = [
        "MNL_0_1090944.dat",
        "MNL_1090944_1091520.dat",
        "MNL_1091520_1091808.dat",
        "MNL_1091808_1092096.dat",
        "MNL_1092096_1092336.dat",
        "MNL_1092336_1092360.dat",
        "MNL_1092360_1092384.dat",
        "MNL_1092384_1092408.dat",
        "MNL_1092408_1092432.dat",
        "MNL_1092432_1092456.dat",
        "MNL_1092456_1092480.dat",
        "MNL_1092480_1092504.dat",
        "MNL_1092504_1092528.dat",
        "MNL_1092528_1092552.dat",
        "MNL_1092552_1092576.dat",
        "MNL_1092576_1092600.dat",
        "MNL_1092600_1092624.dat",
        "MNL_1092624_1092648.dat",
        "MNL_1092648_1092672.dat",
        "MNL_1092672_1092696.dat",
        "MNL_1092696_1092720.dat",
        "MNL_1092720_1092744.dat",
        "MNL_1092744_1092768.dat",
        "MNL_1092768_1092792.dat",
        "MNL_1092792_1092816.dat",
        "MNL_1092816_1092840.dat",
        "MNL_1092840_1092864.dat",
        "MNL_1092864_1092888.dat",
        "MNL_1092888_1092916.dat",
    ]
        .map(Into::into)
        .to_vec();

    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache: &mut Default::default(),
        blocks: init_mainnet_store()
    });

    let (success, lists) = load_masternode_lists_for_files(files, true, context);
    assert!(success, "Unsuccessful");
    assert_eq!(lists.len(), 29, "There should be 29 models lists");
}

pub fn load_masternode_lists_for_files(
    files: Vec<String>,
    assert_validity: bool,
    context: &mut FFIContext,
) -> (bool, BTreeMap<UInt256, models::MasternodeList>) {
    let cache = unsafe { &mut *processor_create_cache() };
    let processor = unsafe {
        register_processor(
            context.chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
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
    context.cache = cache;

    for file in files {
        println!("load_masternode_lists_for_files: [{}]", file);
        let bytes = context.chain.load_message(file.as_str());
        let result = unsafe { process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            context.chain,
            false,
            false,
            70221,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )};
        let result = unsafe { &*result };
        println!("result: [{:?}]", result);
        //println!("MNDiff: {} added, {} modified", result.added_masternodes_count, result.modified_masternodes_count);
        if assert_validity {
            assert_diff_result(context, result);
        }
        let block_hash = UInt256(unsafe { *result.block_hash });
        let masternode_list = unsafe { &*result.masternode_list };
        let masternode_list_decoded = unsafe { masternode_list.decode() };
    }
    let lists = context.cache.mn_lists.clone();
    (true, lists)
}
