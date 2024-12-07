use std::sync::Arc;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::tests::FFIContext;
use crate::tests::common::load_masternode_lists_for_files;

#[test]
fn test_quorum_issue() {
    let chain = ChainType::MainNet;
    let files = vec![
        "MNL_0_1096704.dat".to_string(),
        "MNL_1096704_1097280.dat".to_string(),
        "MNL_1097280_1097856.dat".to_string(),
        "MNL_1097856_1098144.dat".to_string(),
        "MNL_1098144_1098432.dat".to_string(),
        "MNL_1098432_1098456.dat".to_string(),
        "MNL_1098456_1098480.dat".to_string(),
        "MNL_1098480_1098504.dat".to_string(),
        "MNL_1098504_1098528.dat".to_string(),
        "MNL_1098528_1098552.dat".to_string(),
        "MNL_1098552_1098576.dat".to_string(),
        "MNL_1098576_1098600.dat".to_string(),
        "MNL_1092576_1092600.dat".to_string(),
        "MNL_1092600_1092624.dat".to_string(),
        "MNL_1092624_1092648.dat".to_string(),
        "MNL_1092648_1092672.dat".to_string(),
        "MNL_1092672_1092696.dat".to_string(),
        "MNL_1092696_1092720.dat".to_string(),
        "MNL_1092720_1092744.dat".to_string(),
        "MNL_1092744_1092768.dat".to_string(),
        "MNL_1092768_1092792.dat".to_string(),
        "MNL_1092792_1092816.dat".to_string(),
        "MNL_1092816_1092840.dat".to_string(),
        "MNL_1092840_1092864.dat".to_string(),
        "MNL_1092864_1092888.dat".to_string(),
        "MNL_1098888_1098912.dat".to_string(),
        "MNL_1098912_1098936.dat".to_string(),
        "MNL_1098936_1098960.dat".to_string(),
        "MNL_1098960_1098984.dat".to_string(),
        "MNL_1098984_1099008.dat".to_string(),
    ];
    let context = Arc::new(FFIContext::create_default_context_and_cache(chain, false));
    // let ctx = context.read().unwrap();
    let success = load_masternode_lists_for_files(files, false, Arc::clone(&context), true, chain);
    assert!(success, "Unsuccessful");
    // let ctx = context.read().unwrap();
    // let cache_lock = ctx.cache.read().unwrap();
    // cache_lock.mn_lists.iter().for_each(|(hash, node)| {
    //     println!("Testing quorum of models list at height {}", ctx.block_for_hash(*hash).unwrap().height);
    // });
}
