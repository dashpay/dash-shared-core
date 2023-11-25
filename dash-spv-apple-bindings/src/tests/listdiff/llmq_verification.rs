use std::collections::BTreeMap;
use std::ptr::null_mut;
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::chain::common::{ChainType, LLMQType};
use dash_spv_masternode_processor::crypto::UInt256;
use crate::ffi::{from::FromFFI, to::ToFFI};
use crate::tests::common::{assert_diff_chain, assert_diff_result, create_default_context_and_cache, process_mnlistdiff, register_default_processor};

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
    let mut context = create_default_context_and_cache(chain, false);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, use_insight_as_backup, true);
    println!("{:?}", result);
    let result_119064 = unsafe { &*result };
    assert_diff_result(&mut context, result_119064);

    let is_valid = result_119064.is_valid();
    println!("is_valid: {}", is_valid);
    let bytes = chain.load_message("MNL_122928_123000__70221.dat");
    let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
    let masternode_list_119064 = unsafe { &*result_119064.masternode_list };
    let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, use_insight_as_backup, true);
    println!("{:?}", result);
    let result_119200 = unsafe { &*result };
    assert_diff_result(&mut context, result_119200);

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

#[test]
fn testnet_llmq_verification_using_processor_and_cache() {
    //testTestnetQuorumVerification
    let chain = ChainType::TestNet;
    let mut context = create_default_context_and_cache(chain, false);
    let processor = register_default_processor(&mut context);
    let use_insight_as_backup = false;

    let bytes = chain.load_message("MNL_0_122928__70221.dat");
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, use_insight_as_backup, false);
    let result_119064 = unsafe { &*result };
    assert_diff_result(&mut context, result_119064);

    let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
    let masternode_list_119064 = unsafe { &*result_119064.masternode_list };
    let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();

    let bytes = chain.load_message("MNL_122928_123000__70221.dat");
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, use_insight_as_backup, false);
    let result_119200 = unsafe { &*result };
    assert_diff_result(&mut context, result_119200);


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
