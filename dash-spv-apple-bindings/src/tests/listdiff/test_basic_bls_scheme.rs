use dash_spv_masternode_processor::block_store::{init_testnet_store, MerkleBlock};
use dash_spv_masternode_processor::chain::common::{ChainType, DevnetType};
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use crate::common::processor_create_cache;
use crate::masternode::process_mnlistdiff_from_message;
use crate::tests::common::{assert_diff_result, create_default_context_and_cache, FFIContext, process_mnlistdiff, register_default_processor};

#[test]
fn test_basic_bls_scheme_using_chacha() {
    let chain = ChainType::DevNet(DevnetType::Chacha);
    let mut context = create_default_context_and_cache(chain, false);
    context.blocks = vec![
        MerkleBlock::new(1, "8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
        MerkleBlock::new(9192, "3a29104cd905e2a584d5f1844a0f421a2af0fd9ad7840a0ebb097a628d1b0000", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
        MerkleBlock::new(9247, "9993903c63b96f9a3846692535a11da2525561f0d61c7d31b7222bfddf020000", "42a84456a608ade07581c35e1087634743f6293c56dbdc01930ad97df0f08b2e"),
    ];
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(chain.load_message("MNL_1_9247.dat"), processor, &mut context, 70224, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
}

#[test]
fn test_core_19_rc_2_testnet() {
    let chain = ChainType::TestNet;
    let cache = unsafe { &mut *processor_create_cache() };
    let context = &mut (FFIContext {
        chain,
        is_dip_0024: false,
        cache,
        blocks: init_testnet_store()
    });
    let processor = register_default_processor(context);
    let bytes = chain.load_message("MNL_TESTNET_CORE_19.dat");
    let result = unsafe { process_mnlistdiff_from_message(
        bytes.as_ptr(),
        bytes.len(),
        chain,
        false,
        true,
        70223,
        processor,
        context.cache,
        context as *mut _ as *mut std::ffi::c_void,
    )};
    let result = unsafe { &*result };
    println!("Result: {:#?}", result);
    assert!(result.has_valid_llmq_list_root, "invalid llmq root {}", UInt256(unsafe { *result.block_hash }));

    // todo: need add new blocks to the testnet store
    // assert_diff_result(context, result);
}
