use dash_spv_masternode_processor::block_store::init_testnet_store;
use crate::tests::common::assert_diff_chain;

#[test]
fn test_mnl_saving_to_disk() {
    // testMNLSavingToDisk
    assert_diff_chain(
        dash_spv_crypto::network::ChainType::TestNet,
        &["ML_at_122088__70221.dat"],
        &[],
        Some(init_testnet_store()), false);
}
