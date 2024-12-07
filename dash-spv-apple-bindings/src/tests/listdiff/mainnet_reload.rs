use std::sync::Arc;
use dash_spv_crypto::network::chain_type::ChainType;
use dash_spv_masternode_processor::tests::FFIContext;
use crate::tests::common::load_masternode_lists_for_files;

#[test]
fn test_mainnet_reload_with_processor() {
    let chain = ChainType::MainNet;
    let files = [
        "MNL_0_1090944.dat",
        "MNL_1090944_1091520.dat",
        "MNL_1091520_1091808.dat",
        "MNL_1091808_1092096.dat",
        "MNL_1092096_1092336.dat",
        "MNL_1092336_1092360.dat",
        "MNL_1092360_1092384.dat",
        "MNL_1092384_1092408.dat",
        "MNL_1092408_1092432.dat",
        "MNL_1092432_1092456.dat",
        "MNL_1092456_1092480.dat",
        "MNL_1092480_1092504.dat",
        "MNL_1092504_1092528.dat",
        "MNL_1092528_1092552.dat",
        "MNL_1092552_1092576.dat",
        "MNL_1092576_1092600.dat",
        "MNL_1092600_1092624.dat",
        "MNL_1092624_1092648.dat",
        "MNL_1092648_1092672.dat",
        "MNL_1092672_1092696.dat",
        "MNL_1092696_1092720.dat",
        "MNL_1092720_1092744.dat",
        "MNL_1092744_1092768.dat",
        "MNL_1092768_1092792.dat",
        "MNL_1092792_1092816.dat",
        "MNL_1092816_1092840.dat",
        "MNL_1092840_1092864.dat",
        "MNL_1092864_1092888.dat",
        "MNL_1092888_1092916.dat",
    ]
        .map(Into::into)
        .to_vec();

    let context = Arc::new(FFIContext::create_default_context_and_cache(chain, false));
    let success = load_masternode_lists_for_files(files, true, Arc::clone(&context), false, chain);
    assert!(success, "Unsuccessful");
    // let context_lock = context.read().unwrap();
    // let cache_lock = context_lock.cache.read().unwrap();
    // assert_eq!(cache_lock.mn_lists.len(), 29, "There should be 29 models lists");
}
