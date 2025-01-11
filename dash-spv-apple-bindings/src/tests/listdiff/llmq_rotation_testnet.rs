use std::collections::BTreeMap;
use std::ptr::null;
use std::sync::Arc;
use hashes::hex::ToHex;
use dash_spv_crypto::crypto::byte_util::{Reversable, Reversed, UInt256};
use dash_spv_crypto::network::{ChainType, LLMQType};
use dash_spv_masternode_processor::hashes::hex::FromHex;
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::models::llmq;
use dash_spv_masternode_processor::models::llmq::validate_payload;
use dash_spv_masternode_processor::processing::CoreProviderError;
use dash_spv_masternode_processor::test_helpers::{block_hash_to_block_hash, load_message};
use dash_spv_masternode_processor::tests::serde_helper::{ListDiff, masternode_list_from_genesis_diff, QRInfo};
use crate::ffi_core_provider::FFICoreProvider;
use crate::tests::common::FFIContext;
#[test]
fn mainnet_quorum_quarters() {
    let chain = ChainType::MainNet;
    let chain_identifier = chain.identifier();
    let block_height_8792 = 1738792;
    let block_height_8840 = 1738840;
    let block_height_8888 = 1738888;
    let chain = ChainType::MainNet;
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain.clone(), true));
    // let provider = FFICoreProvider::register_default(Arc::clone(&context), Arc::new(MasternodeProcessorCache::default()));
    // let cache = context.write().unwrap();
    let processor = FFICoreProvider::default_processor(context, chain.clone());
    // processor.cache.cache_block_height_for_hash(UInt256::from_hex("0000000000000000000").unwrap().0, block_height_8792);

    let qrinfo_8792: QRInfo = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738792.txt")).unwrap();
    let qrinfo_8840: QRInfo = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738840.txt")).unwrap();
    let qrinfo_8888: QRInfo = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738888.txt")).unwrap();
    let qrinfo_8936: QRInfo = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738936.txt")).unwrap();

    let diff_8792: ListDiff = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738792_diff.txt")).unwrap();
    let diff_8840: ListDiff = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738840_diff.txt")).unwrap();
    let diff_8888: ListDiff = serde_json::from_slice(&load_message(chain_identifier.clone(),"1738888_diff.txt")).unwrap();

    let list_diff_8792 = masternode_list_from_genesis_diff(diff_8792, &processor, false);
    let list_diff_8840 = masternode_list_from_genesis_diff(diff_8840, &processor, false);
    let list_diff_8888 = masternode_list_from_genesis_diff(diff_8888, &processor, false);
    // let list_diff_8792 = masternode_list_from_genesis_diff(diff_8792, |_| block_height_8792, false);
    // let list_diff_8840 = masternode_list_from_genesis_diff(diff_8840, |_| block_height_8840, false);
    // let list_diff_8888 = masternode_list_from_genesis_diff(diff_8888, |_| block_height_8888, false);

    let block_hash_8792 = list_diff_8792.block_hash;
    let block_hash_8840 = list_diff_8840.block_hash;
    let block_hash_8888 = list_diff_8888.block_hash;
    println!("block_hash_8792: {}", block_hash_8792.to_hex());
    println!("block_hash_8840: {}", block_hash_8840.to_hex());
    println!("block_hash_8888: {}", block_hash_8888.to_hex());
    let added_quorums_8792 = list_diff_8792.added_quorums.iter()
        .fold(BTreeMap::new(), |mut acc, entry| {
            acc.entry(entry.llmq_type.clone())
                .or_insert_with(BTreeMap::new)
                .insert(entry.llmq_hash, entry.clone());
            acc
        });
    let added_quorums_8840 = list_diff_8840.added_quorums.iter()
        .fold(BTreeMap::new(), |mut acc, entry| {
            acc.entry(entry.llmq_type.clone())
                .or_insert_with(BTreeMap::new)
                .insert(entry.llmq_hash, entry.clone());
            acc
        });
    let added_quorums_8888 = list_diff_8888.added_quorums.iter()
        .fold(BTreeMap::new(), |mut acc, entry| {
            acc.entry(entry.llmq_type.clone())
                .or_insert_with(BTreeMap::new)
                .insert(entry.llmq_hash, entry.clone());
            acc
    });
    let masternode_list_8792 = models::MasternodeList::new(list_diff_8792.added_or_modified_masternodes, added_quorums_8792, block_hash_8792, block_height_8792, true);
    let masternode_list_8840 = models::MasternodeList::new(list_diff_8840.added_or_modified_masternodes, added_quorums_8840, block_hash_8840, block_height_8840, true);
    let masternode_list_8888 = models::MasternodeList::new(list_diff_8888.added_or_modified_masternodes, added_quorums_8888, block_hash_8888, block_height_8888, true);


    let bytes = load_message(chain_identifier.clone(),"QRINFO_0_1739226.dat");
    let old_bytes = load_message(chain_identifier.clone(),"QRINFO_0_1740902.dat");
    let old_bytes2 = load_message(chain_identifier.clone(),"QRINFO_0_1740910.dat");
    processor.cache.add_masternode_list(block_hash_8792, Arc::new(masternode_list_8792));
    processor.cache.add_masternode_list(block_hash_8840, Arc::new(masternode_list_8840));
    processor.cache.add_masternode_list(block_hash_8888, Arc::new(masternode_list_8888));
    // processor.provider.save_masternode_list(block_hash_8792, &masternode_list_8792);
    // processor.provider.save_masternode_list(block_hash_8840, &masternode_list_8840);
    // processor.provider.save_masternode_list(block_hash_8888, &masternode_list_8888);


    let snapshot_8792_h_c = models::LLMQSnapshot::from(qrinfo_8792.quorum_snapshot_at_hminus_c);
    let snapshot_8792_h_2c = models::LLMQSnapshot::from(qrinfo_8792.quorum_snapshot_at_hminus2c);
    let snapshot_8792_h_3c = models::LLMQSnapshot::from(qrinfo_8792.quorum_snapshot_at_hminus3c);
    let snapshot_8840_h_c = models::LLMQSnapshot::from(qrinfo_8840.quorum_snapshot_at_hminus_c);
    let snapshot_8840_h_2c = models::LLMQSnapshot::from(qrinfo_8840.quorum_snapshot_at_hminus2c);
    let snapshot_8840_h_3c = models::LLMQSnapshot::from(qrinfo_8840.quorum_snapshot_at_hminus3c);
    let snapshot_8888_h_c = models::LLMQSnapshot::from(qrinfo_8888.quorum_snapshot_at_hminus_c);
    let snapshot_8888_h_2c = models::LLMQSnapshot::from(qrinfo_8888.quorum_snapshot_at_hminus2c);
    let snapshot_8888_h_3c = models::LLMQSnapshot::from(qrinfo_8888.quorum_snapshot_at_hminus3c);
    let snapshot_8936_h_c = models::LLMQSnapshot::from(qrinfo_8936.quorum_snapshot_at_hminus_c);
    let snapshot_8936_h_2c = models::LLMQSnapshot::from(qrinfo_8936.quorum_snapshot_at_hminus2c);
    let snapshot_8936_h_3c = models::LLMQSnapshot::from(qrinfo_8936.quorum_snapshot_at_hminus3c);

    let block_hash_8792_h_c = block_hash_to_block_hash(qrinfo_8792.mn_list_diff_at_hminus_c.block_hash).reversed();
    let block_hash_8792_h_2c = block_hash_to_block_hash(qrinfo_8792.mn_list_diff_at_hminus2c.block_hash).reversed();
    let block_hash_8792_h_3c = block_hash_to_block_hash(qrinfo_8792.mn_list_diff_at_hminus3c.block_hash).reversed();
    let block_hash_8840_h_c = block_hash_to_block_hash(qrinfo_8840.mn_list_diff_at_hminus_c.block_hash).reversed();
    let block_hash_8840_h_2c = block_hash_to_block_hash(qrinfo_8840.mn_list_diff_at_hminus2c.block_hash).reversed();
    let block_hash_8840_h_3c = block_hash_to_block_hash(qrinfo_8840.mn_list_diff_at_hminus3c.block_hash).reversed();
    let block_hash_8888_h_c = block_hash_to_block_hash(qrinfo_8888.mn_list_diff_at_hminus_c.block_hash).reversed();
    let block_hash_8888_h_2c = block_hash_to_block_hash(qrinfo_8888.mn_list_diff_at_hminus2c.block_hash).reversed();
    let block_hash_8888_h_3c = block_hash_to_block_hash(qrinfo_8888.mn_list_diff_at_hminus3c.block_hash).reversed();
    let block_hash_8936_h_c = block_hash_to_block_hash(qrinfo_8936.mn_list_diff_at_hminus_c.block_hash).reversed();
    let block_hash_8936_h_2c = block_hash_to_block_hash(qrinfo_8936.mn_list_diff_at_hminus2c.block_hash).reversed();
    let block_hash_8936_h_3c = block_hash_to_block_hash(qrinfo_8936.mn_list_diff_at_hminus3c.block_hash).reversed();

    let mut llmq_snapshots_lock = processor.cache.llmq_snapshots.write().unwrap();

    llmq_snapshots_lock.insert(block_hash_8792_h_c, snapshot_8792_h_c);
    llmq_snapshots_lock.insert(block_hash_8792_h_2c, snapshot_8792_h_2c);
    llmq_snapshots_lock.insert(block_hash_8792_h_3c, snapshot_8792_h_3c);
    llmq_snapshots_lock.insert(block_hash_8840_h_c, snapshot_8840_h_c);
    llmq_snapshots_lock.insert(block_hash_8840_h_2c, snapshot_8840_h_2c);
    llmq_snapshots_lock.insert(block_hash_8840_h_3c, snapshot_8840_h_3c);
    llmq_snapshots_lock.insert(block_hash_8888_h_c, snapshot_8888_h_c);
    llmq_snapshots_lock.insert(block_hash_8888_h_2c, snapshot_8888_h_2c);
    llmq_snapshots_lock.insert(block_hash_8888_h_3c, snapshot_8888_h_3c);
    llmq_snapshots_lock.insert(block_hash_8936_h_c, snapshot_8936_h_c);
    llmq_snapshots_lock.insert(block_hash_8936_h_2c, snapshot_8936_h_2c);
    llmq_snapshots_lock.insert(block_hash_8936_h_3c, snapshot_8936_h_3c);
    drop(llmq_snapshots_lock);


    let old_result = processor.qr_info_result_from_message(&old_bytes, true, 70221, true, false, null());
    let old_result2 = processor.qr_info_result_from_message(&old_bytes2, true, 70221, true, false, null());
    let result = processor.qr_info_result_from_message(&bytes, true, 70221, true, false, null());
    // let last_quorum = result.unwrap().last_quorum_per_index.first().expect("Last llmq persist");

    let active_quorums = processor.cache.active_quorums.read().unwrap();

    let llmq_type = LLMQType::Llmqtype60_75;
    let block_hash = UInt256::from_hex("64bd1057ab434352e4e26fe235412f37a8de6b4cb215ca580a00000000000000").unwrap().0;
    let mut target_quorum = active_quorums.iter().find(|q| block_hash.eq(&q.llmq_hash)).cloned()
        .expect("Target quorum");
    // let mut last_quorum = active_quorums.iter().last().unwrap().clone();
    let block_height = 1738944;
    // let block_hash = last_quorum.llmq_hash;
    // let llmq_type = last_quorum.llmq_type;

    // let old_result = process_qr_info(&processor, &old_bytes, true, 70221, true, context.cache);
    // let old_result2 = process_qr_info(&processor, &old_bytes2, true, 70221, true, context.cache);
    // let result = process_qr_info(&processor, &bytes, true, 70221, true, context.cache);
    // let result = result.unwrap();
    // let last_quorum_per_index = unsafe { *(&*result.last_quorum_per_index) };
    // let mut last_quorum = unsafe { { &*(last_quorum_per_index.add(0)) }.decode() };
    // let block_hash = last_quorum.llmq_hash;
    // let llmq_type = last_quorum.llmq_type;
    // let mut last_quorum = result.last_quorum_per_index.first().cloned().unwrap();
    let nodes = processor.get_rotated_masternodes_for_quorum(
        llmq_type,
        block_hash,
        block_height,
        false,
    ).unwrap();
    let node_hashes = nodes.iter().map(|m| m.provider_registration_transaction_hash.clone()).collect::<Vec<[u8; 32]>>();
    let needed_hashes = [
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap().reverse().0,
        UInt256::from_hex("82dcf337825f4eb6726ffe56ab981034c49785c1f92da274e51fe925380265a6").unwrap().reverse().0,
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap().reverse().0,
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap().reverse().0,
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap().reverse().0,
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap().reverse().0,
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap().reverse().0,
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap().reverse().0,
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap().reverse().0,
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap().reverse().0,
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap().reverse().0,
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap().reverse().0,
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap().reverse().0,
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap().reverse().0,
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap().reverse().0,
        UInt256::from_hex("c1666e28121c0e2375e785edcbd2e84e1136f9fa0e415a9310d203aaa06e2153").unwrap().reverse().0,
        UInt256::from_hex("c75b5aaf2a9c127b3f4199d4700abc1eab9fb8ebdf31b4d296951ce395bd52e0").unwrap().reverse().0,
        UInt256::from_hex("7878b048a1411dc9e7cc71b4d3aae6f4bdb93f299f186fee4cc7a4833a7114a7").unwrap().reverse().0,
        UInt256::from_hex("2899b3e2bb291e84943ab9436f93e0708cbb59860f9c05b41ffac4678dd714a5").unwrap().reverse().0,
        UInt256::from_hex("320cac56da899ad7b5133d7d0aa54d0f12d2a7fddea9c97c6749e2a7efdf0b98").unwrap().reverse().0,
        UInt256::from_hex("93bd23b7357a62c5ab2cc306054bf0b1fa6f52265fbbef23f600298d8daebd1a").unwrap().reverse().0,
        UInt256::from_hex("f9d8fbb02e8f909b7922cc34b8259ea6b73dab88738c2af2e02e1ac929ccdd5e").unwrap().reverse().0,
        UInt256::from_hex("b86f9ae4178a3425abb8053a40e1eb138b2a68b466ba2b3bd04167060cd5c1b5").unwrap().reverse().0,
        UInt256::from_hex("d2f9d05f8983ce1d645487efbc4c3b2c31b8ec914b1e9085e70202001e11bcd4").unwrap().reverse().0,
        UInt256::from_hex("c98ab7576c4b83d94e668f0e3910aa514a6ff0171684f9fc8e30143664d20999").unwrap().reverse().0,
        UInt256::from_hex("70f8c30d741529a6ffd4e080993523709b00ad45e6026a19097e13f68d687d55").unwrap().reverse().0,
        UInt256::from_hex("4f45b42e8b170dac1cfe288815423020135e105f4c98e1b2f09db0cf059d1ac6").unwrap().reverse().0,
        UInt256::from_hex("a8ac86f944f9477ba1642bc3f45dba51bb020af43afc1c0ca2f1f1910be209be").unwrap().reverse().0,
        UInt256::from_hex("fdb28cd79093c2a6be18f7b168f50008125a2416984ac4126dab6c8646657dd6").unwrap().reverse().0,
        UInt256::from_hex("8e483b9308737fe836d71967ddb634559a5c63c8cb8d495275952e0f6cb5a717").unwrap().reverse().0,
        UInt256::from_hex("9389d805cb14e9cb6af5afa7c75136507a4a42e1e5bbffb6703dc57ed10de429").unwrap().reverse().0,
        UInt256::from_hex("92a22ba783087016770ff1acae996253a8a3803566aee90d914c3adf9f611116").unwrap().reverse().0,
        UInt256::from_hex("390e6b731013c3da296b61a7365b9954c5a403c95f997e89bf979469f9c1d704").unwrap().reverse().0,
        UInt256::from_hex("867fc5a33fdc09b811cc4a7a307a3ca082a3adc3bc8511ed67e81cc6884ba68d").unwrap().reverse().0,
        UInt256::from_hex("784a0529d150a44ee26ec8f08ab1eaab0d0651ed2ee1f8e611a4304626448e79").unwrap().reverse().0,
        UInt256::from_hex("4016510e2ef1b82fc571781b5a0cd8afa268d0c21b5d352f8f8929c542d1aef3").unwrap().reverse().0,
        UInt256::from_hex("776cbacfaeafd9880d791357c00c5085ddc8d00af507a35dad37c3d0f7a24256").unwrap().reverse().0,
        UInt256::from_hex("5480f489c2e7d4e9992349a0eb85b4a81796979c66a5f2c67f5df05866e01df1").unwrap().reverse().0,
        UInt256::from_hex("5ec696060fb6d43e5065e858a590b98af558c1e0d48d1a08b634189131b17ee7").unwrap().reverse().0,
        UInt256::from_hex("17e5abab4d2bc5b03d14163d57bd0b3014bd7ec56a1051b8bded4373b0d08ba7").unwrap().reverse().0,
        UInt256::from_hex("754285ad30ce2aa5f9d799770a2e06afff77613e09c240d3019d1f266e2f1167").unwrap().reverse().0,
        UInt256::from_hex("68b9a31205e3c190346a162f29804feeee0fe17caa3bda09c1d97e4913967b56").unwrap().reverse().0,
        UInt256::from_hex("b0219f34cc8fccaf88796889a8cd034eac82415cd7f7f3baae950c841857f85c").unwrap().reverse().0,
        UInt256::from_hex("e8f49c2f481b18d8b3ffdfe36dd7cce85bbd0332cd723b7b329d2192cef1fb61").unwrap().reverse().0,
        UInt256::from_hex("7fd0a504278a1e6a0cc1188c98178c279667450502a87e8e841dfaab7896657b").unwrap().reverse().0,
        UInt256::from_hex("168162f349bd2961fab43cd0a19a7e6a34c7a18d5dbe4805c06a4fcbcb138e78").unwrap().reverse().0,
        UInt256::from_hex("758d75feab2349545b83db14acb101419bd8874118a493587bce5ed344ad959d").unwrap().reverse().0,
        UInt256::from_hex("db6fbedc75d6acd52b505d9f553716255c8e25b434f8df211a190bc17dd7e4ff").unwrap().reverse().0,
        UInt256::from_hex("d74519d65b78ab5c34c8c8bf8951e967a35ebc17b2eaea3f5d1fbe719583d5fd").unwrap().reverse().0,
        UInt256::from_hex("56d86d05eb95672667a7f7a5fa8908617e4f7624a1d2897e49469e2a591b65d3").unwrap().reverse().0,
        UInt256::from_hex("d3ddea9366c7deb606d1ba58e2911a3958d81f887dc8c1af69e6f90a0b0ec8df").unwrap().reverse().0,
        UInt256::from_hex("f0cf643f2098605eb570f22a72d6fb93735563e35c5b9bb93885236d5388e0f6").unwrap().reverse().0,
        UInt256::from_hex("af6ab1210c32d3e0c8c1425402986c0563c926173e71a85410b20e04d9728579").unwrap().reverse().0,
        UInt256::from_hex("5b9bb413ec3d6dd8c7675471c28be5a12196ca73eec70a84f96648987f28220e").unwrap().reverse().0,
        UInt256::from_hex("4030316b3a1aaa4aa174e94e7c82fd847e116a50cc280bf37a44a94215ebd747").unwrap().reverse().0,
        UInt256::from_hex("65c11e751596f3e2f8829b41bce171d872d3a0e9bd6ea8b65757f61b47b6d50d").unwrap().reverse().0,
        UInt256::from_hex("35584dc1f4cc507012648a42b30c9aaaee19d028abd16ee31c87a04bf4a91470").unwrap().reverse().0,
        UInt256::from_hex("d802702597a6c8a2d8e6011f5ff365595db3893d5531c65ecd5be63c8dfc13c9").unwrap().reverse().0,
        UInt256::from_hex("d66ba16f114b921b3e48c7a0681ba465a68f09029a130999859cb0abb48a0717").unwrap().reverse().0,
        UInt256::from_hex("fac4265c8c8213b069b75bb3c565309accb214631bff9cfb41a4ec1b6feda7fc").unwrap().reverse().0
    ];
    // println!("##############");
    // println!("{:#?}", node_hashes);
    // println!("##############");
    // println!("{:#?}", needed_hashes);
    // println!("##############");
    // assert_eq!(node_hashes, needed_hashes, "Quorum Combo must be equal");

    let new_quarter_members = [
        UInt256::from_hex("168162f349bd2961fab43cd0a19a7e6a34c7a18d5dbe4805c06a4fcbcb138e78").unwrap().reverse().0,
        UInt256::from_hex("758d75feab2349545b83db14acb101419bd8874118a493587bce5ed344ad959d").unwrap().reverse().0,
        UInt256::from_hex("db6fbedc75d6acd52b505d9f553716255c8e25b434f8df211a190bc17dd7e4ff").unwrap().reverse().0,
        UInt256::from_hex("d74519d65b78ab5c34c8c8bf8951e967a35ebc17b2eaea3f5d1fbe719583d5fd").unwrap().reverse().0,
        UInt256::from_hex("56d86d05eb95672667a7f7a5fa8908617e4f7624a1d2897e49469e2a591b65d3").unwrap().reverse().0,
        UInt256::from_hex("d3ddea9366c7deb606d1ba58e2911a3958d81f887dc8c1af69e6f90a0b0ec8df").unwrap().reverse().0,
        UInt256::from_hex("f0cf643f2098605eb570f22a72d6fb93735563e35c5b9bb93885236d5388e0f6").unwrap().reverse().0,
        UInt256::from_hex("af6ab1210c32d3e0c8c1425402986c0563c926173e71a85410b20e04d9728579").unwrap().reverse().0,
        UInt256::from_hex("5b9bb413ec3d6dd8c7675471c28be5a12196ca73eec70a84f96648987f28220e").unwrap().reverse().0,
        UInt256::from_hex("4030316b3a1aaa4aa174e94e7c82fd847e116a50cc280bf37a44a94215ebd747").unwrap().reverse().0,
        UInt256::from_hex("65c11e751596f3e2f8829b41bce171d872d3a0e9bd6ea8b65757f61b47b6d50d").unwrap().reverse().0,
        UInt256::from_hex("35584dc1f4cc507012648a42b30c9aaaee19d028abd16ee31c87a04bf4a91470").unwrap().reverse().0,
        UInt256::from_hex("d802702597a6c8a2d8e6011f5ff365595db3893d5531c65ecd5be63c8dfc13c9").unwrap().reverse().0,
        UInt256::from_hex("d66ba16f114b921b3e48c7a0681ba465a68f09029a130999859cb0abb48a0717").unwrap().reverse().0,
        UInt256::from_hex("fac4265c8c8213b069b75bb3c565309accb214631bff9cfb41a4ec1b6feda7fc").unwrap().reverse().0
    ];
    //assert_eq!(node_hashes, new_quarter_members, "Quorum Combo must be equal");
    let quarter_h_c = [
        UInt256::from_hex("9389d805cb14e9cb6af5afa7c75136507a4a42e1e5bbffb6703dc57ed10de429").unwrap().reverse().0,
        UInt256::from_hex("92a22ba783087016770ff1acae996253a8a3803566aee90d914c3adf9f611116").unwrap().reverse().0,
        UInt256::from_hex("390e6b731013c3da296b61a7365b9954c5a403c95f997e89bf979469f9c1d704").unwrap().reverse().0,
        UInt256::from_hex("867fc5a33fdc09b811cc4a7a307a3ca082a3adc3bc8511ed67e81cc6884ba68d").unwrap().reverse().0,
        UInt256::from_hex("784a0529d150a44ee26ec8f08ab1eaab0d0651ed2ee1f8e611a4304626448e79").unwrap().reverse().0,
        UInt256::from_hex("4016510e2ef1b82fc571781b5a0cd8afa268d0c21b5d352f8f8929c542d1aef3").unwrap().reverse().0,
        UInt256::from_hex("776cbacfaeafd9880d791357c00c5085ddc8d00af507a35dad37c3d0f7a24256").unwrap().reverse().0,
        UInt256::from_hex("5480f489c2e7d4e9992349a0eb85b4a81796979c66a5f2c67f5df05866e01df1").unwrap().reverse().0,
        UInt256::from_hex("5ec696060fb6d43e5065e858a590b98af558c1e0d48d1a08b634189131b17ee7").unwrap().reverse().0,
        UInt256::from_hex("17e5abab4d2bc5b03d14163d57bd0b3014bd7ec56a1051b8bded4373b0d08ba7").unwrap().reverse().0,
        UInt256::from_hex("754285ad30ce2aa5f9d799770a2e06afff77613e09c240d3019d1f266e2f1167").unwrap().reverse().0,
        UInt256::from_hex("68b9a31205e3c190346a162f29804feeee0fe17caa3bda09c1d97e4913967b56").unwrap().reverse().0,
        UInt256::from_hex("b0219f34cc8fccaf88796889a8cd034eac82415cd7f7f3baae950c841857f85c").unwrap().reverse().0,
        UInt256::from_hex("e8f49c2f481b18d8b3ffdfe36dd7cce85bbd0332cd723b7b329d2192cef1fb61").unwrap().reverse().0,
        UInt256::from_hex("7fd0a504278a1e6a0cc1188c98178c279667450502a87e8e841dfaab7896657b").unwrap().reverse().0,
    ];
    let quarter_h_2c = [
        UInt256::from_hex("c1666e28121c0e2375e785edcbd2e84e1136f9fa0e415a9310d203aaa06e2153").unwrap().reverse().0,
        UInt256::from_hex("c75b5aaf2a9c127b3f4199d4700abc1eab9fb8ebdf31b4d296951ce395bd52e0").unwrap().reverse().0,
        UInt256::from_hex("7878b048a1411dc9e7cc71b4d3aae6f4bdb93f299f186fee4cc7a4833a7114a7").unwrap().reverse().0,
        UInt256::from_hex("2899b3e2bb291e84943ab9436f93e0708cbb59860f9c05b41ffac4678dd714a5").unwrap().reverse().0,
        UInt256::from_hex("320cac56da899ad7b5133d7d0aa54d0f12d2a7fddea9c97c6749e2a7efdf0b98").unwrap().reverse().0,
        UInt256::from_hex("93bd23b7357a62c5ab2cc306054bf0b1fa6f52265fbbef23f600298d8daebd1a").unwrap().reverse().0,
        UInt256::from_hex("f9d8fbb02e8f909b7922cc34b8259ea6b73dab88738c2af2e02e1ac929ccdd5e").unwrap().reverse().0,
        UInt256::from_hex("b86f9ae4178a3425abb8053a40e1eb138b2a68b466ba2b3bd04167060cd5c1b5").unwrap().reverse().0,
        UInt256::from_hex("d2f9d05f8983ce1d645487efbc4c3b2c31b8ec914b1e9085e70202001e11bcd4").unwrap().reverse().0,
        UInt256::from_hex("c98ab7576c4b83d94e668f0e3910aa514a6ff0171684f9fc8e30143664d20999").unwrap().reverse().0,
        UInt256::from_hex("70f8c30d741529a6ffd4e080993523709b00ad45e6026a19097e13f68d687d55").unwrap().reverse().0,
        UInt256::from_hex("4f45b42e8b170dac1cfe288815423020135e105f4c98e1b2f09db0cf059d1ac6").unwrap().reverse().0,
        UInt256::from_hex("a8ac86f944f9477ba1642bc3f45dba51bb020af43afc1c0ca2f1f1910be209be").unwrap().reverse().0,
        UInt256::from_hex("fdb28cd79093c2a6be18f7b168f50008125a2416984ac4126dab6c8646657dd6").unwrap().reverse().0,
        UInt256::from_hex("8e483b9308737fe836d71967ddb634559a5c63c8cb8d495275952e0f6cb5a717").unwrap().reverse().0
    ];
    let quarter_h_3c = [
        UInt256::from_hex("d2426992844e311149b2962f4ea991656ea5d1b36541e314e251915a6ffa1316").unwrap().reverse().0,
        UInt256::from_hex("82dcf337825f4eb6726ffe56ab981034c49785c1f92da274e51fe925380265a6").unwrap().reverse().0,
        UInt256::from_hex("30c14c1d75694404dbc96d44d1c63f28bf685d27e44ef753883c5eb0742c5805").unwrap().reverse().0,
        UInt256::from_hex("631a5e99e59bab2bf06e4ec9874b3c3ced59187dc724c689ffa0fe99f2d3f210").unwrap().reverse().0,
        UInt256::from_hex("113673823cf38eb56f30795d7f830b2d82b70a35b96812ad79d0889465b69df3").unwrap().reverse().0,
        UInt256::from_hex("0e01a796d779a8494be44311d6daf07fdae8642b45a9b866024cd97d8dfd3545").unwrap().reverse().0,
        UInt256::from_hex("feb146a52985cbf69f0a46b3a56f5f505538440bd42e993a0685a11fac1fdda5").unwrap().reverse().0,
        UInt256::from_hex("48d665ade991114900349635c788775204057220728212e2b6b63e3545f67007").unwrap().reverse().0,
        UInt256::from_hex("adcc454391d9f53e6fa523e047db5f335e38d9ead70dc8e4e648118c285d1d77").unwrap().reverse().0,
        UInt256::from_hex("aadd2eac24d6cc9a0b439d3c9d5483b0ed64ebda21786760bb375efacd6e2a67").unwrap().reverse().0,
        UInt256::from_hex("a90df0c30b2002a85cef6b695b986a3815c7dc82027c6896b7747258675a76da").unwrap().reverse().0,
        UInt256::from_hex("e13fbad0ab0bca68cbcd4d68127de06037b4007c5acbe8550edcd60b7d4503e8").unwrap().reverse().0,
        UInt256::from_hex("200ccffb2ef1da266efda63b35bc80bc8a547f29af3b8108f81ab222a1ceac35").unwrap().reverse().0,
        UInt256::from_hex("21173e00737bac467d09effb15959d0459b853160805057a3975436d3e206591").unwrap().reverse().0,
        UInt256::from_hex("321a1300b3ec63b3082d1626c7377d3c9e4e332eadefe12073f5e17b5099a49e").unwrap().reverse().0,
    ];
    assert_eq!(node_hashes[..15], quarter_h_3c, "Quorum quarter at H - 3C is wrong");
    assert_eq!(node_hashes[15..30], quarter_h_2c, "Quorum quarter at H - 2C is wrong");
    assert_eq!(node_hashes[30..45], quarter_h_c, "Quorum quarter at H - C is wrong");
    assert_eq!(node_hashes[45..], new_quarter_members, "New quorum quarter members are wrong");
    println!("last_quorum: {:?}", target_quorum);

    let payload_validation_status = validate_payload(&target_quorum);
    assert!(payload_validation_status.is_ok(), "Invalid payload");
    let result = llmq::validate(&mut target_quorum, nodes, block_height);
    assert!(matches!(result, Ok(()) | Err(CoreProviderError::MissedMasternodeListAt(..))), "Invalid signature");
}
