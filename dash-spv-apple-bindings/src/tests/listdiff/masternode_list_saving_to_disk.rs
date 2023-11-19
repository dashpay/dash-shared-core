use dash_spv_masternode_processor::chain::common::chain_type::ChainType;
use crate::tests::common::assert_diff_chain;

#[test]
fn test_mnl_saving_to_disk() {
    // testMNLSavingToDisk
    assert_diff_chain(
        ChainType::TestNet,
        &["ML_at_122088__70221.dat"],
        &[],
        None);
}
