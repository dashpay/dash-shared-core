use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::models::MasternodeList;
use dash_spv_masternode_processor::test_helpers::{load_message, masternode_list_from_json, message_from_file};
use dash_spv_masternode_processor::tests::serde_helper::MNList;
use crate::tests::common::{create_default_context_and_cache, process_mnlistdiff, register_default_processor};

#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let bytes = load_message(chain.identifier(),"MNL_1761054_1761100.dat");
    let mut context = create_default_context_and_cache(chain, false);
    let list_1761054 = serde_json::from_slice(&message_from_file("mainnet/MNLIST_1761054_1666771101.811508_saveMasternodeList.json"))?;
    let list_1761048 = serde_json::from_slice(&message_from_file("mainnet/MNLIST_1761048_1666773093.153379_saveMasternodeList.json"))?;
    let masternode_list_1761054 = MasternodeList::from(list_1761054);
    let masternode_list_1761048 = MasternodeList::from(list_1761048);
    context.cache.mn_lists.insert(masternode_list_1761048.block_hash, masternode_list_1761048);
    context.cache.mn_lists.insert(masternode_list_1761054.block_hash, masternode_list_1761054);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(bytes, processor, &mut context, 70221, false, true);
    // println!("{:#?}", result);
    // assert_diff_result(context, result);
}

