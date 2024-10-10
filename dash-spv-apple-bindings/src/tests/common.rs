use std::{fs, io::Read, ptr::null_mut};
use std::collections::BTreeMap;
use ferment::boxed;
use dash_spv_masternode_processor::chain::common::{ChainType, IHaveChainSettings};
use dash_spv_masternode_processor::crypto::byte_util::{BytesDecodable, Reversable, UInt256, UInt768};
use dash_spv_masternode_processor::hashes::hex::{FromHex, ToHex};
use dash_spv_masternode_processor::logger::register_rust_logger;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache, ProcessingError};
use dash_spv_masternode_processor::block_store::{init_mainnet_store, init_testnet_store, MerkleBlock};
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::test_helpers::Block;
use crate::common::{processor_create_cache, register_processor};
use crate::ffi::{from::FromFFI, to::ToFFI};
use crate::ffi_core_provider::FFICoreProvider;
use crate::masternode::{process_mnlistdiff_from_message, process_qrinfo_from_message};
use crate::types;

extern crate libc;
extern crate reqwest;

pub fn get_block_from_insight_by_hash(hash: UInt256) -> Option<MerkleBlock> {
    let path = format!("https://testnet-insight.dashevo.org/insight-api-dash/block/{}", hash.reversed().0.to_hex().as_str());
    request_block(path)
}
pub fn get_block_from_insight_by_height(height: u32) -> Option<MerkleBlock> {
    let path = format!("https://testnet-insight.dashevo.org/insight-api-dash/block/{}", height);
    request_block(path)
}

pub fn request_block(path: String) -> Option<MerkleBlock> {
    println!("request_block: {}", path.as_str());
    match reqwest::blocking::get(path.as_str()) {
        Ok(response) => match response.json::<serde_json::Value>() {
            Ok(json) => {
                let block: Block = serde_json::from_value(json).unwrap();
                let merkle_block = MerkleBlock {
                    hash: UInt256::from_hex(block.hash.as_str()).unwrap().reverse(),
                    height: block.height as u32,
                    merkleroot: UInt256::from_hex(block.merkleroot.as_str()).unwrap()
                };
                println!("request_block: {}", path.as_str());
                Some(merkle_block)
            },
            Err(err) => {
                println!("{}", err);
                None
            },
        },
        Err(err) => {
            println!("{}", err);
            None
        },
    }
}


#[derive(Debug)]
pub struct FFIContext<'a> {
    pub chain: ChainType,
    pub is_dip_0024: bool,
    pub cache: &'a mut MasternodeProcessorCache,
    // TODO:: make it initialized from json file with blocks
    pub blocks: Vec<MerkleBlock>,
}

impl<'a> FFIContext<'a> {
    pub fn block_for_hash(&self, hash: UInt256) -> Option<&MerkleBlock> {
        self.blocks.iter().find(|block| block.hash == hash)
    }
    pub fn block_for_height(&self, height: u32) -> Option<&MerkleBlock> {
        self.blocks.iter().find(|block| block.height == height)
    }

    pub fn genesis_as_ptr(&self) -> *const u8 {
        self.chain.genesis_hash().0.as_ptr()
    }
}

pub fn register_logger() {
    unsafe { register_rust_logger(); }
}

pub fn register_default_processor(context: &mut FFIContext) -> *mut MasternodeProcessor {
    unsafe {
        register_processor(
            context.chain,
            get_merkle_root_by_hash_default,
            get_block_height_by_hash_from_context,
            get_block_hash_by_height_from_context,
            get_llmq_snapshot_by_block_hash_from_context,
            save_llmq_snapshot_in_cache,
            get_cl_signature_by_block_hash_from_context,
            save_cl_signature_in_cache,
            get_masternode_list_by_block_hash_from_cache,
            masternode_list_save_in_cache,
            masternode_list_destroy_default,
            add_insight_lookup_default,
            hash_destroy_default,
            snapshot_destroy_default,
            should_process_diff_with_range_default,
            context as *mut _ as *mut std::ffi::c_void
        )
    }
}

pub fn process_mnlistdiff(bytes: Vec<u8>, processor: *mut MasternodeProcessor, context: &mut FFIContext, protocol_version: u32, use_insight: bool, is_from_snapshot: bool) -> *mut types::MNListDiffResult {
    unsafe {
        process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            context.chain,
            use_insight,
            is_from_snapshot,
            protocol_version,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )
    }
}

pub fn process_qrinfo(bytes: Vec<u8>, processor: *mut MasternodeProcessor, context: &mut FFIContext, version: u32, use_insight: bool, is_from_snapshot: bool) -> *mut types::QRInfoResult {
    unsafe {
        process_qrinfo_from_message(
            bytes.as_ptr(),
            bytes.len(),
            context.chain,
            use_insight,
            is_from_snapshot,
            true,
            version,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )
    }
}
pub fn create_default_context_and_cache<'a>(chain: ChainType, is_dip_0024: bool) -> FFIContext<'a> {
    let cache = unsafe { &mut *processor_create_cache() };
    create_default_context(chain, is_dip_0024, cache)
}

pub fn create_default_context(chain: ChainType, is_dip_0024: bool, cache: &mut MasternodeProcessorCache) -> FFIContext {
    let blocks = match chain {
        ChainType::MainNet => init_mainnet_store(),
        ChainType::TestNet => init_testnet_store(),
        _ => vec![],
    };
    FFIContext { chain, is_dip_0024, cache, blocks }
}

pub fn assert_diff_result(context: &mut FFIContext, result: &types::MNListDiffResult) {
    let masternode_list = unsafe { (*result.masternode_list).decode() };
    //print!("block_hash: {} ({})", masternode_list.block_hash, masternode_list.block_hash.reversed());
    let bh = context.block_for_hash(masternode_list.block_hash).map_or(u32::MAX, |b| b.height);
    assert!(result.has_found_coinbase, "has no coinbase {}", bh);
    //turned off on purpose as we don't have the coinbase block
    //assert!(result.has_valid_coinbase, "Coinbase not valid at height {}", bh);
    assert!(result.has_valid_mn_list_root, "invalid mnl root {}", bh);
    assert!(result.has_valid_llmq_list_root, "invalid llmq root {}", bh);
    assert!(result.has_valid_quorums, "has invalid llmq height {}", bh);
    println!("Diff is ok at {}", bh);
}

pub unsafe extern "C" fn get_merkle_root_by_hash_from_insight(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> *mut u8 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let hash = UInt256(*block_hash);
    match data.blocks.iter().find(|block| block.hash == hash) {
        Some(block) => boxed(block.merkleroot.reversed().0) as *mut _,
        None => match get_block_from_insight_by_hash(hash) {
            Some(block) => {
                data.blocks.push(block);
                boxed(block.merkleroot.reversed().0) as *mut _
            },
            None => boxed(UInt256::MIN.0) as *mut _
        }
    }
}

pub fn assert_qrinfo_result(context: &mut FFIContext, result: &types::QRInfoResult) {
    if result.mn_list_diff_list_count > 0 {
        let diff_result = unsafe { &**result.mn_list_diff_list };
        assert_diff_result(context, diff_result);
    }
    if result.extra_share {
        assert_diff_result(context, unsafe { &*result.result_at_h_4c });
    }
    assert_diff_result(context, unsafe { &*result.result_at_h_3c });
    assert_diff_result(context, unsafe { &*result.result_at_h_2c });
    assert_diff_result(context, unsafe { &*result.result_at_h_c });
    assert_diff_result(context, unsafe { &*result.result_at_h });
    assert_diff_result(context, unsafe { &*result.result_at_tip });
}

pub unsafe extern "C" fn get_block_height_by_hash_from_context(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> u32 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let block_hash = UInt256(*block_hash);
    let block_hash_reversed = block_hash.reversed();
    let block = data.block_for_hash(block_hash).unwrap_or(&MerkleBlock { hash: UInt256::MIN, height: u32::MAX, merkleroot: UInt256::MIN });
    let height = block.height;
    // println!("get_block_height_by_hash_from_context {}: {} ({})", height, block_hash_reversed, block_hash);
    if height == u32::MAX {
        println!("{}: {},", height, block_hash_reversed);
    }
    height
}

pub unsafe extern "C" fn get_block_hash_by_height_default(
    _block_height: u32,
    _context: *const std::ffi::c_void,
) -> *mut u8 {
    null_mut()
}

pub unsafe extern "C" fn get_block_hash_by_height_from_context(
    block_height: u32,
    context: *const std::ffi::c_void,
) -> *mut u8 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    if let Some(block) = data.block_for_height(block_height) {
        let block_hash = block.hash;
        // println!("get_block_hash_by_height_from_context: {}: {:?}", block_height, block_hash.clone().reversed());
        boxed(block_hash.0) as *mut _
    } else {
        null_mut()
    }
}

pub unsafe extern "C" fn get_llmq_snapshot_by_block_height_default(
    _block_height: u32,
    _context: *const std::ffi::c_void,
) -> *mut types::LLMQSnapshot {
    null_mut()
}

pub unsafe extern "C" fn get_llmq_snapshot_by_block_hash_default(
    _block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *mut types::LLMQSnapshot {
    null_mut()
}

pub unsafe extern "C" fn get_llmq_snapshot_by_block_hash_from_context(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut types::LLMQSnapshot {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    if let Some(snapshot) = data.cache.llmq_snapshots.get(&h) {
        //println!("get_llmq_snapshot_by_block_hash_from_context: {}: {:?}", h, snapshot);
        boxed(snapshot.encode())
    } else {
        null_mut()
    }
}

pub unsafe extern "C" fn get_cl_signature_by_block_hash_from_context(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut u8 {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    if let Some(sig) = data.cache.cl_signatures.get(&h) {
        boxed(sig.0) as *mut _
    } else {
        null_mut()
    }
}

pub unsafe extern "C" fn get_masternode_list_by_block_hash_default(
    _block_hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) -> *mut types::MasternodeList {
    null_mut()
}

pub unsafe extern "C" fn get_masternode_list_by_block_hash_from_cache(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut types::MasternodeList {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    //println!("get_masternode_list_by_block_hash_from_cache: {}", h);
    if let Some(list) = data.cache.mn_lists.get(&h) {
        // println!("get_masternode_list_by_block_hash_from_cache: {}: masternodes: {} quorums: {} mn_merkle_root: {:?}, llmq_merkle_root: {:?}", h, list.masternodes.len(), list.quorums.len(), list.masternode_merkle_root, list.llmq_merkle_root);
        let encoded = list.encode();
        // &encoded as *const types::MasternodeList
        boxed(encoded)
    } else {
        println!("missing list: {}: {},", get_block_height_by_hash_from_context(block_hash, context), h.reversed());
        null_mut()
    }
}

pub unsafe extern "C" fn masternode_list_save_default(
    _block_hash: *mut [u8; 32],
    _masternode_list: *mut types::MasternodeList,
    _context: *const std::ffi::c_void,
) -> bool {
    true
}
pub unsafe extern "C" fn masternode_list_save_in_cache(
    block_hash: *mut [u8; 32],
    masternode_list: *mut types::MasternodeList,
    context: *const std::ffi::c_void,
) -> bool {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let masternode_list_decoded = (&*masternode_list).decode();
    //println!("masternode_list_save_in_cache: {}", h);
    data.cache.mn_lists.insert(h, masternode_list_decoded);
    true
}

pub unsafe extern "C" fn masternode_list_destroy_default(
    _masternode_list: *mut types::MasternodeList,
) {
}
pub unsafe extern "C" fn hash_destroy_default(_hash: *mut u8) {}

pub unsafe extern "C" fn should_process_diff_with_range_default(
    base_block_hash: *mut [u8; 32],
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> ProcessingError {
    ProcessingError::None
}
pub unsafe extern "C" fn snapshot_destroy_default(_snapshot: *mut types::LLMQSnapshot) {}
pub unsafe extern "C" fn add_insight_lookup_default(
    _hash: *mut [u8; 32],
    _context: *const std::ffi::c_void,
) {
}
pub unsafe extern "C" fn save_llmq_snapshot_default(
    block_hash: *mut [u8; 32],
    snapshot: *mut types::LLMQSnapshot,
    _context: *const std::ffi::c_void,
) -> bool {
    true
}
pub unsafe extern "C" fn save_llmq_snapshot_in_cache(
    block_hash: *mut [u8; 32],
    snapshot: *mut types::LLMQSnapshot,
    context: *const std::ffi::c_void,
) -> bool {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    data.cache.add_snapshot(h, (*snapshot).decode());
    true
}
pub unsafe extern "C" fn save_cl_signature_in_cache(
    block_hash: *mut [u8; 32],
    cl_signature: *mut [u8; 96],
    context: *const std::ffi::c_void,
) -> bool {
    let h = UInt256(*(block_hash));
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    data.cache.add_cl_signature(h, UInt768(*cl_signature));
    true
}

pub unsafe extern "C" fn get_merkle_root_by_hash_default(
    block_hash: *mut [u8; 32],
    context: *const std::ffi::c_void,
) -> *mut u8 {
    let block_hash = UInt256(*block_hash);
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let block_hash_reversed = block_hash.reversed().0.to_hex();
    let merkle_root = if let Some(block) = data.block_for_hash(block_hash) {
        block.merkleroot.reversed()
    } else {
        UInt256::from_hex("0000000000000000000000000000000000000000000000000000000000000000").unwrap()
    };
    //println!("get_merkle_root_by_hash_default {} ({}) => ({})", block_hash, block_hash_reversed, merkle_root);
    boxed(merkle_root.0) as *mut _
}

pub unsafe extern "C" fn get_block_hash_by_height_from_insight(block_height: u32, context: *const std::ffi::c_void) -> *mut u8 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    match data.blocks.iter().find(|block| block.height == block_height) {
        Some(block) => boxed(block.hash.0) as *mut _,
        None => match get_block_from_insight_by_height(block_height) {
            Some(block) => {
                data.blocks.push(block);
                boxed(block.hash.0) as *mut _
            },
            None => null_mut()
        }
    }
}

pub unsafe extern "C" fn get_block_height_by_hash_from_insight(block_hash: *mut [u8; 32], context: *const std::ffi::c_void) -> u32 {
    let data: &mut FFIContext = &mut *(context as *mut FFIContext);
    let hash = UInt256(*block_hash);
    match data.blocks.iter().find(|block| block.hash == hash) {
        Some(block) => block.height,
        None => match get_block_from_insight_by_hash(hash) {
            Some(block) => {
                data.blocks.push(block);
                block.height
            }
            None => u32::MAX
        }
    }
}

pub fn get_file_as_byte_vec(filename: &str) -> Vec<u8> {
    //println!("get_file_as_byte_vec: {}", filename);
    if let (Ok(mut f), Ok(metadata)) = (fs::File::open(&filename), fs::metadata(&filename)) {
        let mut buffer = vec![0; metadata.len() as usize];
        if let Ok(()) = f.read_exact(&mut buffer) {
            return buffer;
        }
    }
    panic!("get_file_as_byte_vec: error for: {}", filename)
}

pub fn perform_mnlist_diff_test_for_message(
    hex_string: &str,
    should_be_total_transactions: u32,
    verify_string_hashes: Vec<&str>,
    verify_string_smle_hashes: Vec<&str>,
) {
    let bytes = Vec::from_hex(hex_string).unwrap();
    let length = bytes.len();
    let c_array = bytes.as_ptr();
    let message: &[u8] = unsafe { std::slice::from_raw_parts(c_array, length) };
    let chain = ChainType::TestNet;
    let offset = &mut 0;
    assert!(length - *offset >= 32);
    let base_block_hash = UInt256::from_bytes(message, offset).unwrap();
    assert_ne!(base_block_hash, UInt256::default(), "Base block hash should NOT be empty here");
    assert!(length - *offset >= 32);
    let _block_hash = UInt256::from_bytes(message, offset).unwrap();
    assert!(length - *offset >= 4);
    let total_transactions = u32::from_bytes(message, offset).unwrap();
    assert_eq!(total_transactions, should_be_total_transactions, "Invalid transaction count");
    let use_insight_as_backup = false;
    let base_masternode_list_hash: *const u8 = null_mut();
    let mut context = create_default_context_and_cache(chain, false);
    let processor = register_default_processor(&mut context);
    let result = unsafe { &*process_mnlistdiff_from_message(
        c_array,
        length,
        chain,
        use_insight_as_backup,
        true,
        70221,
        processor,
        context.cache,
        &mut context as *mut _ as *mut std::ffi::c_void,
    )};
    println!("result: {:?}", result);
    let masternode_list = unsafe { (*result.masternode_list).decode() };
    let masternodes = masternode_list.masternodes;
    let mut pro_tx_hashes: Vec<UInt256> = masternodes.clone().into_keys().collect();
    pro_tx_hashes.sort();
    let mut verify_hashes: Vec<UInt256> = verify_string_hashes
        .into_iter()
        .map(|h| UInt256::from_hex(h).unwrap().reverse())
        .collect();
    verify_hashes.sort();
    assert_eq!(verify_hashes, pro_tx_hashes, "Provider transaction hashes");
    let mut masternode_list_hashes: Vec<UInt256> = pro_tx_hashes
        .clone()
        .iter()
        .map(|hash| masternodes[hash].entry_hash)
        .collect();
    masternode_list_hashes.sort();
    let mut verify_smle_hashes: Vec<UInt256> = verify_string_smle_hashes
        .into_iter()
        // TODO: figure out why it now works without reversing
        // .map(|h| UInt256::from_hex(h).unwrap().reverse())
        .map(|h| UInt256::from_hex(h).unwrap())
        .collect();
    verify_smle_hashes.sort();
    assert_eq!(masternode_list_hashes, verify_smle_hashes, "SMLE transaction hashes");
    assert!(result.has_found_coinbase, "The coinbase was not part of provided hashes");
}

pub fn load_masternode_lists_for_files(
    files: Vec<String>,
    assert_validity: bool,
    context: &mut FFIContext,
) -> (bool, BTreeMap<UInt256, models::MasternodeList>) {
    let processor = register_default_processor(context);
    for file in files {
        let bytes = context.chain.load_message(file.as_str());
        let result = unsafe { process_mnlistdiff_from_message(
            bytes.as_ptr(),
            bytes.len(),
            context.chain,
            false,
            false,
            70221,
            processor,
            context.cache,
            context as *mut _ as *mut std::ffi::c_void,
        )};
        let result = unsafe { &*result };
        if assert_validity {
            assert_diff_result(context, result);
        }
        let block_hash = UInt256(unsafe { *result.block_hash });
        let masternode_list = unsafe { &*result.masternode_list };
        let masternode_list_decoded = unsafe { masternode_list.decode() };
    }
    let lists = context.cache.mn_lists.clone();
    (true, lists)
}
pub fn extract_protocol_version_from_filename(filename: &str) -> Option<u32> {
    filename.split("__")
        .nth(1)
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<u32>().ok())
}

pub fn assert_diff_chain(chain: ChainType, diff_files: &[&'static str], qrinfo_files: &[&'static str], block_store: Option<Vec<MerkleBlock>>) {
    register_logger();
    let context = &mut create_default_context_and_cache(chain, false);
    if let Some(blocks) = block_store {
        context.blocks = blocks;
    }
    let processor = register_default_processor(context);
    diff_files.iter().for_each(|filename| {
        let protocol_version = extract_protocol_version_from_filename(filename).unwrap_or(70219);
        let result = process_mnlistdiff(chain.load_message(filename), processor, context, protocol_version, false, true);
        let result = unsafe { &*result };
        assert_diff_result(context, result);
        unsafe {
            context.cache.mn_lists.insert(UInt256(*result.block_hash), (*result.masternode_list).decode());
        }
    });
    context.is_dip_0024 = true;
    qrinfo_files.iter().for_each(|filename| {
        let protocol_version = extract_protocol_version_from_filename(filename).unwrap_or(70219);
        let result = process_qrinfo(chain.load_message(filename), processor, context, protocol_version, false, true);
        let result = unsafe { &*result };
        assert_qrinfo_result(context, result);
        unsafe {
            if !result.result_at_h_4c.is_null() {
                let result_at_h_4c = &*result.result_at_h_4c;
                context.cache.mn_lists.insert(UInt256(*result_at_h_4c.block_hash), (*result_at_h_4c.masternode_list).decode());
            }
            let result_at_h_3c = &*result.result_at_h_3c;
            context.cache.mn_lists.insert(UInt256(*result_at_h_3c.block_hash), (*result_at_h_3c.masternode_list).decode());
            let result_at_h_2c = &*result.result_at_h_2c;
            context.cache.mn_lists.insert(UInt256(*result_at_h_2c.block_hash), (*result_at_h_2c.masternode_list).decode());
            let result_at_h_c = &*result.result_at_h_c;
            context.cache.mn_lists.insert(UInt256(*result_at_h_c.block_hash), (*result_at_h_c.masternode_list).decode());
            let result_at_h = &*result.result_at_h;
            context.cache.mn_lists.insert(UInt256(*result_at_h.block_hash), (*result_at_h.masternode_list).decode());
            let result_at_tip = &*result.result_at_tip;
            context.cache.mn_lists.insert(UInt256(*result_at_tip.block_hash), (*result_at_tip.masternode_list).decode());
        }
    });
}