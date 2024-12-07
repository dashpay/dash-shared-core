use std::ptr::null;
use std::sync::Arc;
use dash_spv_masternode_processor::block_store::MerkleBlock;
use dash_spv_crypto::network::{ChainType, DevnetType};
use dash_spv_masternode_processor::test_helpers::load_message;
use dash_spv_masternode_processor::tests::FFIContext;
use crate::ffi_core_provider::FFICoreProvider;

#[test]
fn test_basic_bls_scheme_using_chacha() {
    let chain = DevnetType::Chacha;
    let message = load_message(chain.identifier(), "MNL_1_9247.dat");
    let context = Arc::new(FFIContext::devnet_default(
        chain,
        false,
        vec![
            MerkleBlock::new(1, "8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
            MerkleBlock::new(9192, "3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
            MerkleBlock::new(9247, "9993903c63b96f9a3846692535a11da2525561f0d61c7d31b7222bfddf020000", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
    ]));
    let processor = FFICoreProvider::default_processor(Arc::clone(&context), ChainType::DevNet(chain));
    // let mut ctx = context.write().unwrap();
    // let processor = MasternodeProcessor::new(Arc::new(provider));
    let (block_hash, _) = processor.mn_list_diff_result_from_message(&message, true, 70224, false, null())
        .expect("failed to process diff");
    let masternode_list = processor.masternode_list_for_block_hash(block_hash).expect("MasternodeList");
    let bh = context.block_for_hash(masternode_list.block_hash)
        .map(|b| b.height)
        .unwrap_or(u32::MAX);
    // assert!(result.has_found_coinbase, "has no coinbase {}", bh);
    // assert!(result.has_valid_mn_list_root, "invalid mnl root {}", bh);
    // assert!(result.has_valid_llmq_list_root, "invalid llmq root {}", bh);
    // assert!(result.has_valid_quorums, "has invalid llmq height {}", bh);
    println!("Diff is ok at {}", bh);

}

#[test]
fn test_core_19_rc_2_testnet() {
    let chain = ChainType::TestNet;
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain, false));
    let processor = FFICoreProvider::default_processor(Arc::clone(&context), chain);
    // let mut ctx = context.write().unwrap();
    // let processor = MasternodeProcessor::new(Arc::new(provider));
    let bytes = load_message(chain.identifier(), "MNL_TESTNET_CORE_19.dat");
    let result = processor.mn_list_diff_result_from_message(&bytes, true, 70223, false, null())
        .expect("failed to process mnlistdiff");
    // assert!(result.has_valid_llmq_list_root, "invalid llmq root {}", result.block_hash.0.to_hex());

    // todo: need add new blocks to the testnet store
    // assert_diff_result(context, result);
}
