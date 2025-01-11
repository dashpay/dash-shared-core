use std::ptr::{null, null_mut};
use std::sync::Arc;
use hashes::hex::FromHex;
use dash_spv_crypto::crypto::UInt256;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::block_store::init_testnet_store;
use dash_spv_masternode_processor::test_helpers::load_message;
use dash_spv_masternode_processor::tests::FFIContext;
use crate::ffi_core_provider::FFICoreProvider;
use crate::tests::common::assert_diff_chain;

#[test]
fn testnet_llmq_verificationx() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_122928__70221.dat", "MNL_122928_123000__70221.dat"],
        &[],
        Some(init_testnet_store()), false);
}

#[test]
fn testnet_llmq_verification() {
    //testTestnetQuorumVerification
    let chain = ChainType::TestNet;
    let bytes = load_message(chain.identifier().as_str(), "MNL_0_122928__70221.dat");
    let use_insight_as_backup = false;
    let base_masternode_list_hash: *const u8 = null_mut();
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain.clone(), false));
    let processor = FFICoreProvider::default_processor(Arc::clone(&context), chain.clone());
    // let mut ctx = context.write().unwrap();
    // let processor = MasternodeProcessor::new(Arc::new(provider));
    let result_119064 = processor.mn_list_diff_result_from_message(&bytes, true, 70221, false, null())
        .expect("Unable to process mn_list_diff");
    // assert_diff_result(&ctx, &result_119064);

    // let is_valid = result_119064.is_valid();
    // println!("is_valid: {}", is_valid);
    let bytes = load_message(chain.identifier(), "MNL_122928_123000__70221.dat");
    let block_hash_119064 = &result_119064.0;
    // let block_hash_119064 = UInt256(unsafe { *result_119064.block_hash });
    // let masternode_list_119064 = unsafe { &*result_119064.masternode_list };
    // let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    // let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();
    let result_119200 = processor.mn_list_diff_result_from_message(&bytes, true, 70221, false, null())
        .expect("Unable to process mn_list_diff");
    // assert_diff_result(&ctx, &result_119200);

    // let masternode_list_119200 = unsafe { &*result_119200.masternode_list };
    // let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
    // let added_quorums = result_119200.added_quorums.iter()
    //     .fold(BTreeMap::new(), |mut acc, entry| {
    //         acc.entry(entry.llmq_type)
    //             .or_insert_with(BTreeMap::new)
    //             .insert(entry.llmq_hash, entry.clone());
    //         acc
    //     });
    // let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = added_quorums
    //     .into_iter()
    //     .filter(|(_, map)| map.contains_key(block_hash_119064))
    //     .collect();
    // assert!(!hmm.is_empty(), "There should be a quorum using 119064");
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
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain.clone(), false));
    let processor = FFICoreProvider::default_processor(Arc::clone(&context), chain.clone());
    let use_insight_as_backup = false;
    let bytes = load_message(chain.identifier(), "MNL_0_122928__70221.dat");
    let result_119064 = processor.mn_list_diff_result_from_message(&bytes, false, 70221, false, null())
        .expect("Unable to process mn_list_diff");
    let block_hash_119064 = result_119064.0;
    let bb1 = UInt256::from_hex("23b8cd5303c892c0b140152f256c7ff27645890e04f93dc7df75d90100000000").unwrap().0;
    // let hash_119024 = UInt256::from_hex("2cbcf83b62913d56f605c0e581a48872839428c92e5eb76cd7ad94bcaf0b0000").unwrap().0;
    let list_119064 = processor.masternode_list_for_block_hash(bb1).unwrap();
    processor.cache.add_masternode_list(block_hash_119064, list_119064);
    let masternode_list_119064 = processor.masternode_list_for_block_hash(block_hash_119064)
        .expect("MasternodeList");
    // let masternode_list_119064 = result_119064.masternode_list;
    // let masternode_list_119064_decoded = unsafe { masternode_list_119064.decode() };
    // let masternode_list_119064_encoded = masternode_list_119064_decoded.encode();

    let bytes = load_message(chain.identifier(), "MNL_122928_123000__70221.dat");
    let result_119200 = processor.mn_list_diff_result_from_message(&bytes, false, 70221, false, null())
        .expect("Unable to process mn_list_diff");
    // let result = process_mnlistdiff(bytes, processor, &mut context, 70221, use_insight_as_backup, false);
    // let result_119200 = unsafe { &*result };
    // assert_diff_result(&ctx, &result_119200);


    // let masternode_list_119200 = result_119200.masternode_list;
    let masternode_list_119200 = processor.masternode_list_for_block_hash(result_119200.0)
        .expect("MasternodeList");

    // let masternode_list_119200_decoded = unsafe { masternode_list_119200.decode() };
    // let added_quorums = result_119200.added_quorums.iter().fold(BTreeMap::new(), |mut acc, entry| {
    //     // let llmq_type = map.llmq_type;
    //     // let llmq_hash = UInt256(*map.llmq_hash);
    //     acc.entry(entry.llmq_type)
    //         .or_insert_with(BTreeMap::new)
    //         .insert(entry.llmq_hash, entry.clone());
    //     acc
    // });
    // let added_quorums = (0..result_119200.added_quorums_count)
    //     .into_iter()
    //     .fold(BTreeMap::new(), |mut acc, i| unsafe {
    //         let map = &*(*(result_119200.added_quorums.add(i)));
    //         let llmq_type = map.llmq_type;
    //         let llmq_hash = UInt256(*map.llmq_hash);
    //         acc.entry(llmq_type)
    //             .or_insert_with(BTreeMap::new)
    //             .insert(llmq_hash, map.decode());
    //         acc
    //     });
    // let hmm: BTreeMap<LLMQType, BTreeMap<UInt256, LLMQEntry>> = added_quorums
    //     .into_iter()
    //     .filter(|(_, map)| map.contains_key(&block_hash_119064))
    //     .collect();
    // assert!(!hmm.is_empty(), "There should be a quorum using 119064");
    // assert!(added_quorums.contains_key(&block_hash_119064), "There should be a quorum using 119064");
    // TODO: verify with QuorumValidationData (need implement BLS before)
    //let quorum_to_verify = added_quorums[&block_hash_119064];
    //quorum_to_verify.validate_with_masternode_list(masternode_list_119064_decoded);
    //assert!(quorum_to_verify.verified, "Unable to verify quorum");
}
