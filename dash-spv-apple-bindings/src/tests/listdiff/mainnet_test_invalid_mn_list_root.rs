use dash_spv::chain::common::ChainType;
use dash_spv_masternode_processor::test_helpers::{load_message, masternode_list_from_json};
use crate::tests::common::{create_default_context_and_cache, process_mnlistdiff, register_default_processor};

#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let bytes = load_message(chain.iden,"MNL_1761054_1761100.dat");
    let mut context = create_default_context_and_cache(chain, false);
    let masternode_list_1761054 = masternode_list_from_json("mainnet/MNLIST_1761054_1666771101.811508_saveMasternodeList.json".to_string());
    let masternode_list_1761048 = masternode_list_from_json("mainnet/MNLIST_1761048_1666773093.153379_saveMasternodeList.json".to_string());
    context.cache.mn_lists.insert(masternode_list_1761048.block_hash, masternode_list_1761048);
    context.cache.mn_lists.insert(masternode_list_1761054.block_hash, masternode_list_1761054);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, false, true);
    // println!("{:#?}", result);
    // assert_diff_result(context, result);
}

