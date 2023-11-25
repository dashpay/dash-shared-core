use dash_spv_masternode_processor::chain::common::{ChainType, IHaveChainSettings};
use dash_spv_masternode_processor::crypto::{byte_util::Reversable, UInt256};
use dash_spv_masternode_processor::test_helpers::{masternode_list_from_genesis_diff, QRInfo, snapshot_to_snapshot};
use crate::tests::common::{create_default_context_and_cache, register_default_processor};

#[test]
pub fn test_from_snapshot() {
    let chain = ChainType::TestNet;
    let qrinfo: QRInfo = serde_json::from_slice(&chain.load_message("snapshot_0000021715c8575620382ceee42cc7556bac5ed395eaf9c75e2119aa2876a1e0.json")).unwrap();
    let mut context = create_default_context_and_cache(chain, true);
    let processor = unsafe { &mut *register_default_processor(&mut context) };
    let block_height_lookup = |hash: UInt256| context.block_for_hash(hash).unwrap().height;
    let quorum_snapshot_h_c = snapshot_to_snapshot(qrinfo.quorum_snapshot_at_hminus_c);
    let quorum_snapshot_h_2c = snapshot_to_snapshot(qrinfo.quorum_snapshot_at_hminus2c);
    let quorum_snapshot_h_3c = snapshot_to_snapshot(qrinfo.quorum_snapshot_at_hminus3c);
    let mn_list_diff_tip = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_tip, block_height_lookup, false);
    let mn_list_diff_h = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_h, block_height_lookup, false);
    let mn_list_diff_h_c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus_c, block_height_lookup, false);
    let mn_list_diff_h_2c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus2c, block_height_lookup, false);
    let mn_list_diff_h_3c = masternode_list_from_genesis_diff(qrinfo.mn_list_diff_at_hminus3c, block_height_lookup, false);

    // println!("rotated_quorums at h ({}: {})", mn_list_diff_h.block_height, mn_list_diff_h.block_hash);
    let cached_blocks = &context.blocks;
    let get_height = |hash: UInt256| cached_blocks.iter().find(|block| block.hash == hash.reversed()).unwrap().height;
    let cached_llmq_members = &mut context.cache.llmq_members;
    let cached_llmq_indexed_members = &mut context.cache.llmq_indexed_members;

    mn_list_diff_h.added_quorums.iter().filter(|q| q.llmq_type == chain.isd_llmq_type()).for_each(|entry| {
        // println!("rotated_quorum: ({}: {})", entry.llmq_hash, entry.llmq_hash.reversed());
        let llmq_block_height = get_height(entry.llmq_hash);
        // println!("rotated_quorum: ({}: {})\n {:#?}", llmq_block_height, entry.llmq_hash, entry);
        let masternodes = processor.get_rotated_masternodes_for_quorum(
            entry.llmq_type,
            entry.llmq_hash,
            llmq_block_height,
            false,
            &mut context.cache
        );
        // println!("masternodes: {:#?}", masternodes);
    });

    // let masternodes = processor
    //     .get_rotated_masternodes_for_quorum(chain.isd_llmq_type(), mn_list_diff_h.added_quorums)


    // let result_at_tip = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_tip, cache);
    // let result_at_h = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h, cache);
    // let result_at_h_c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_c, cache);
    // let result_at_h_2c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_2c, cache);
    // let result_at_h_3c = processor.get_list_diff_result_internal_with_base_lookup(mn_list_diff_h_3c, cache);
    // println!("result_at_tip: {:#?}", result_at_tip);
    // println!("result_at_h: {:#?}", result_at_h);
    // println!("result_at_h_c: {:#?}", result_at_h_c);
    // println!("result_at_h_2c: {:#?}", result_at_h_2c);
    // println!("result_at_h_3c: {:#?}", result_at_h_3c);
}

