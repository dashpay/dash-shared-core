use std::collections::BTreeMap;
use std::ptr::null_mut;
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::block_store::init_testnet_store;
use dash_spv_masternode_processor::chain::common::{ChainType, LLMQType};
use dash_spv_masternode_processor::crypto::UInt256;
use crate::common::{processor_create_cache, register_processor};
use crate::ffi::{from::FromFFI, to::ToFFI};
use crate::masternode::process_mnlistdiff_from_message;
use crate::tests::common::{add_insight_lookup_default, assert_diff_chain, assert_diff_result, FFIContext, get_block_hash_by_height_default, get_block_height_by_hash_from_context, get_cl_signature_by_block_hash_from_context, get_llmq_snapshot_by_block_hash_default, get_masternode_list_by_block_hash_from_cache, get_merkle_root_by_hash_default, hash_destroy_default, masternode_list_destroy_default, masternode_list_save_in_cache, save_cl_signature_in_cache, save_llmq_snapshot_default, should_process_diff_with_range_default, snapshot_destroy_default};
use crate::types;
#[test]
fn testnet_llmq_verificationx() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_122928__70221.dat", "MNL_122928_123000__70221.dat"],
        &[],
        None);
}

#[test]
fn testnet_llmq_verification() {
    //testTestnetQuorumVerification
    let chain = ChainType::TestNet;
    let bytes = chain.load_message("MNL_0_122928__70221.dat");
    let use_insight_as_backup = false;
    let base_masternode_list_hash: *const u8 = null_mut();
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: init_testnet_store()
    };
    let processor = unsafe {
        register_processor(
            chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            get_cl_signature_by_block_hash_from_context,
            save_cl_signature_in_cache,
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
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        use_insight_as_backup,
        true,
        70221,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    println!("{:?}", result);
    let result_119064 = unsafe { &*result };
    assert_diff_result(context, result_119064);

    let is_valid = result_119064.is_valid();
    println!("is_valid: {}", is_valid);
    let bytes = chain.load_message("MNL_122928_123000__70221.dat");
    let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
    let masternode_list_119064 = unsafe { &*result_119064.masternode_list };
    let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        use_insight_as_backup,
        false,
        70221,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    println!("{:?}", result);
    let result_119200 = unsafe { &*result };
    assert_diff_result(context, result_119200);

    let masternode_list_119200 = unsafe { &*result_119200.masternode_list };
    let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
    let added_quorums = (0..result_119200.added_quorums_count)
        .into_iter()

        .fold(BTreeMap::new(), |mut acc, i| unsafe {
            let map = &*(*(result_119200.added_quorums.add(i)));
            let llmq_type = map.llmq_type;
            let llmq_hash = UInt256(*map.llmq_hash);
            acc.entry(llmq_type)
                .or_insert_with(BTreeMap::new)
                .insert(llmq_hash, map.decode());
            acc
        });
    let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, models::LLMQEntry>> = added_quorums
        .into_iter()
        .filter(|(_, map)| map.contains_key(&block_hash_119064))
        .collect();
    assert!(!hmm.is_empty(), "There should be a quorum using 119064");
    // assert!(added_quorums.contains_key(&block_hash_119064), "There should be a quorum using 119064");
    // TODO: verify with QuorumValidationData (need implement BLS before)
    //let quorum_to_verify = added_quorums[&block_hash_119064];
    //quorum_to_verify.validate_with_masternode_list(masternode_list_119064_decoded);
    //assert!(quorum_to_verify.verified, "Unable to verify quorum");
}

unsafe extern "C" fn get_block_height_by_hash(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> u32 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    if let Some(block) = data.block_for_hash(UInt256(*(block_hash))) {
        block.height
    } else {
        u32::MAX
    }
}

pub unsafe extern "C" fn masternode_list_save_119064(
    block_hash: *mut [u8; 32],
    masternode_list: *mut types::MasternodeList,
    context: *const std::ffi::c_void,
) -> bool {
    let ctx = &mut *(context as *mut FFIContext);
    let h = UInt256(*(block_hash));
    let list = (*masternode_list).decode();
    // ctx.cache.mn_lists.insert(h, list);
    true
}

#[test]
fn testnet_llmq_verification_using_processor_and_cache() {
    //testTestnetQuorumVerification
    let chain = ChainType::TestNet;
    let bytes = chain.load_message("MNL_0_122928__70221.dat");
    let use_insight_as_backup = false;
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: init_testnet_store()
    };
    let processor = unsafe {
        register_processor(
            chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash,
            get_block_hash_by_height_default,
            get_llmq_snapshot_by_block_hash_default,
            save_llmq_snapshot_default,
            get_cl_signature_by_block_hash_from_context,
            save_cl_signature_in_cache,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_119064,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            context as *mut _ as *mut std::ffi::c_void
        )
    };

    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        use_insight_as_backup,
        false,
        70221,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};

    println!("{:?}", result);
    let result_119064 = unsafe { &*result };
    assert_diff_result(context, result_119064);


    let is_valid = result_119064.is_valid();
    assert!(is_valid, "Invalid result");
    let bytes = chain.load_message("MNL_122928_123000__70221.dat");
    let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
    let masternode_list_119064 = unsafe { &*result_119064.masternode_list };
    let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();

    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        use_insight_as_backup,
        false,
        70221,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};

    println!("{:?}", result);
    let result_119200 = unsafe { &*result };
    assert_diff_result(context, result_119200);


    let masternode_list_119200 = unsafe { &*result_119200.masternode_list };
    let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
    let added_quorums = (0..result_119200.added_quorums_count)
        .into_iter()
        .fold(BTreeMap::new(), |mut acc, i| unsafe {
            let map = &*(*(result_119200.added_quorums.add(i)));
            let llmq_type = map.llmq_type;
            let llmq_hash = UInt256(*map.llmq_hash);
            acc.entry(llmq_type)
                .or_insert_with(BTreeMap::new)
                .insert(llmq_hash, map.decode());
            acc
        });
    let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, models::LLMQEntry>> = added_quorums
        .into_iter()
        .filter(|(_, map)| map.contains_key(&block_hash_119064))
        .collect();
    assert!(!hmm.is_empty(), "There should be a quorum using 119064");
    // assert!(added_quorums.contains_key(&block_hash_119064), "There should be a quorum using 119064");
    // TODO: verify with QuorumValidationData (need implement BLS before)
    //let quorum_to_verify = added_quorums[&block_hash_119064];
    //quorum_to_verify.validate_with_masternode_list(masternode_list_119064_decoded);
    //assert!(quorum_to_verify.verified, "Unable to verify quorum");
}
