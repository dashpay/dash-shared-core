use std::ptr::null;
use std::sync::Arc;
use dash_spv_crypto::network::ChainType;
use dash_spv_masternode_processor::models::MasternodeList;
use dash_spv_masternode_processor::test_helpers::{load_message, message_from_file};
use dash_spv_masternode_processor::tests::FFIContext;
use dash_spv_masternode_processor::tests::serde_helper::MNList;
use crate::ffi_core_provider::FFICoreProvider;
// use crate::tests::common::{create_default_context_and_cache, process_mnlistdiff, register_default_processor};

#[test]
fn mainnet_test_invalid_mn_list_root() {
    let chain = ChainType::MainNet;
    let bytes = load_message(chain.identifier(),"MNL_1761054_1761100.dat");
    let context = FFIContext::create_default_context_and_cache(chain.clone(), false);
    let processor = FFICoreProvider::default_processor(Arc::new(context), chain.clone());
    let list_1761054: MNList = serde_json::from_slice(&message_from_file("mainnet/MNLIST_1761054_1666771101.811508_saveMasternodeList.json")).unwrap();
    let list_1761048: MNList = serde_json::from_slice(&message_from_file("mainnet/MNLIST_1761048_1666773093.153379_saveMasternodeList.json")).unwrap();
    let masternode_list_1761054 = MasternodeList::from(list_1761054);
    let masternode_list_1761048 = MasternodeList::from(list_1761048);
    let mut lists_lock = processor.cache.mn_lists.write().unwrap();
    lists_lock.insert(masternode_list_1761048.block_hash, Arc::new(masternode_list_1761048));
    lists_lock.insert(masternode_list_1761054.block_hash, Arc::new(masternode_list_1761054));
    drop(lists_lock);
    let result = processor.mn_list_diff_result_from_message(&bytes, true, 70221, false, null())
        .expect("SUCCESS");
    // let processor = register_default_processor(&mut context);
    // let result = process_mnlistdiff(bytes, processor, &mut context, 70221, false, true);
    // println!("{:#?}", result);
    // assert_diff_result(context, result);
}

