// use std::sync::Arc;
// use dash_spv_crypto::network::{ChainType, IHaveChainSettings};
// use dash_spv_masternode_processor::models::LLMQSnapshot;
// use dash_spv_masternode_processor::test_helpers::load_message;
// use dash_spv_masternode_processor::tests::FFIContext;
// use dash_spv_masternode_processor::tests::serde_helper::{masternode_list_from_genesis_diff, QRInfo};
// use crate::ffi_core_provider::FFICoreProvider;
//
// #[test]
// pub fn test_from_snapshot() {
//     let chain = ChainType::TestNet;
//     let qrinfo: QRInfo = serde_json::from_slice(&load_message(chain.identifier(), "snapshot_0000021715c8575620382ceee42cc7556bac5ed395eaf9c75e2119aa2876a1e0.json")).unwrap();
//     let context = Arc::new(FFIContext::create_default_context_and_cache(chain.clone(), true));
//     let processor = FFICoreProvider::default_processor(context, chain.clone());
//     // let mut context = create_default_context_and_cache(chain, true);
//     // let processor = unsafe { &mut *register_default_processor(&mut context) };
//     // let block_height_lookup = |hash: [u8; 32]| context.block_for_hash(hash).unwrap().height;
//     let quorum_snapshot_h_c = LLMQSnapshot::from(qrinfo.quorum_snapshot_at_hminus_c);
//     let quorum_snapshot_h_2c = LLMQSnapshot::from(qrinfo.quorum_snapshot_at_hminus2c);
//     let quorum_snapshot_h_3c = LLMQSnapshot::from(qrinfo.quorum_snapshot_at_hminus3c);
//     let mn_list_diff_tip = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_tip, &processor, false);
//     let mn_list_diff_h = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_h, &processor, false);
//     let mn_list_diff_h_c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus_c, &processor, false);
//     let mn_list_diff_h_2c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus2c, &processor, false);
//     let mn_list_diff_h_3c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus3c, &processor, false);
//
//     // println!("rotated_quorums at h ({}: {})", mn_list_diff_h.block_height, mn_list_diff_h.block_hash);
//     // let cached_blocks = &context.blocks;
//     // let get_height = |hash: [u8; 32]| cached_blocks.iter().find(|block| block.hash() == hash.reversed()).unwrap().height;
//     // let cached_llmq_members = &mut context.cache.llmq_members;
//     // let cached_llmq_indexed_members = &mut context.cache.llmq_indexed_members;
//
//     mn_list_diff_h.added_quorums.iter().filter(|q| q.llmq_type == chain.isd_llmq_type()).for_each(|entry| {
//         // println!("rotated_quorum: ({}: {})", entry.llmq_hash, entry.llmq_hash.reversed());
//         let llmq_block_height = processor.height_for_block_hash(entry.llmq_hash);
//         // let llmq_block_height = get_height(entry.llmq_hash);
//         // println!("rotated_quorum: ({}: {})\n {:#?}", llmq_block_height, entry.llmq_hash, entry);
//         let masternodes = processor.get_rotated_masternodes_for_quorum(
//             entry.llmq_type,
//             entry.llmq_hash,
//             llmq_block_height,
//             false,
//         );
//         // println!("masternodes: {:#?}", masternodes);
//     });
//
//     // let masternodes = processor
//     //     .get_rotated_masternodes_for_quorum(chain.isd_llmq_type(), mn_list_diff_h.added_quorums)
//
//
//     // let result_at_tip = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_tip, cache);
//     // let result_at_h = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h, cache);
//     // let result_at_h_c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_c, cache);
//     // let result_at_h_2c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_2c, cache);
//     // let result_at_h_3c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_3c, cache);
//     // println!("result_at_tip: {:#?}", result_at_tip);
//     // println!("result_at_h: {:#?}", result_at_h);
//     // println!("result_at_h_c: {:#?}", result_at_h_c);
//     // println!("result_at_h_2c: {:#?}", result_at_h_2c);
//     // println!("result_at_h_3c: {:#?}", result_at_h_3c);
// }
//
