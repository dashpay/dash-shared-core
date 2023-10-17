use std::ffi::CString;
use std::os::raw::c_char;
use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::crypto::byte_util::ConstDecodable;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};
use crate::ffi::callbacks::{AddInsightBlockingLookup, GetBlockHashByHeight, GetBlockHeightByHash, GetLLMQSnapshotByBlockHash, HashDestroy, LLMQSnapshotDestroy, MasternodeListDestroy, MasternodeListLookup, MasternodeListSave, MerkleRootLookup, SaveLLMQSnapshot, ShouldProcessDiffWithRange};
use crate::ffi_core_provider::FFICoreProvider;
use crate::types;


// /// Initializes logger (it could be initialize only once)
// #[no_mangle]
// pub unsafe extern "C" fn register_rust_logger() {
//     // Get the path to the cache directory.
//     let cache_path = match dirs_next::cache_dir() {
//         Some(path) => path,
//         None => panic!("Failed to find the cache directory"),
//     };
//
//     // Create the log directory if it doesn't exist.
//     let log_dir = cache_path.join("Logs");
//     if !log_dir.exists() {
//         std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");
//     }
//
//     // Create the log file inside the cache directory.
//     let log_file_path = log_dir.join("processor.log");
//     println!("Log file create at: {:?}", log_file_path);
//     let log_file = File::create(log_file_path)
//         .expect("Failed to create log file");
//     let config = ConfigBuilder::new().build();
//     //let config = ConfigBuilder::new().set_time_level(LevelFilter::Off).set_max_level(LevelFilter::Off).build();
//     match CombinedLogger::init(
//         vec![
//             TermLogger::new(LevelFilter::Error, config.clone(), TerminalMode::Mixed, ColorChoice::Auto),
//             TermLogger::new(LevelFilter::Warn, config.clone(), TerminalMode::Mixed, ColorChoice::Auto),
//             WriteLogger::new(LevelFilter::Error, config.clone(), log_file.try_clone().unwrap()),
//             WriteLogger::new(LevelFilter::Warn, config.clone(), log_file.try_clone().unwrap()),
//             WriteLogger::new(LevelFilter::Info, config.clone(), log_file.try_clone().unwrap()),
//         ]
//     ) {
//         Ok(()) => println!("Logger initialized"),
//         Err(err) => println!("Failed to init logger: {}", err)
//     }
// }

/// Register all the callbacks for use across FFI
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn register_processor(
    chain_type: ChainType,
    get_merkle_root_by_hash: MerkleRootLookup,
    get_block_height_by_hash: GetBlockHeightByHash,
    get_block_hash_by_height: GetBlockHashByHeight,
    get_llmq_snapshot_by_block_hash: GetLLMQSnapshotByBlockHash,
    save_llmq_snapshot: SaveLLMQSnapshot,
    get_masternode_list_by_block_hash: MasternodeListLookup,
    save_masternode_list: MasternodeListSave,
    destroy_masternode_list: MasternodeListDestroy,
    add_insight: AddInsightBlockingLookup,
    destroy_hash: HashDestroy,
    destroy_snapshot: LLMQSnapshotDestroy,
    should_process_diff_with_range: ShouldProcessDiffWithRange,
    opaque_context: *const std::os::raw::c_void
) -> *mut MasternodeProcessor {
    let provider = FFICoreProvider::new(
        get_merkle_root_by_hash,
        get_block_height_by_hash,
        get_block_hash_by_height,
        get_llmq_snapshot_by_block_hash,
        save_llmq_snapshot,
        get_masternode_list_by_block_hash,
        save_masternode_list,
        destroy_masternode_list,
        add_insight,
        destroy_hash,
        destroy_snapshot,
        should_process_diff_with_range,
        opaque_context,
        chain_type
    );
    let processor = MasternodeProcessor::new(provider);
    println!("register_processor: {:?}", processor);
    ferment_interfaces::boxed(processor)
}

/// Unregister all the callbacks for use across FFI
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn unregister_processor(processor: *mut MasternodeProcessor) {
    println!("unregister_processor: {:?}", processor);
    let unboxed = ferment_interfaces::unbox_any(processor);
}

/// Initialize opaque cache to store needed information between FFI calls
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_create_cache() -> *mut MasternodeProcessorCache {
    let cache = MasternodeProcessorCache::default();
    println!("processor_create_cache: {:?}", cache);
    ferment_interfaces::boxed(cache)
}

/// Destroy opaque cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_destroy_cache: {:?}", cache);
    let cache = ferment_interfaces::unbox_any(cache);
}

/// Remove models list from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_masternode_list_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_masternode_list_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Ok(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_masternode_list(&hash);
    }
}

/// Remove quorum snapshot from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_llmq_snapshot_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_llmq_snapshot_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Ok(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_snapshot(&hash);
    }
}

/// Remove llmq members from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_remove_llmq_members_from_cache_for_block_hash(block_hash: *const u8, cache: *mut MasternodeProcessorCache) {
    println!("processor_remove_llmq_members_from_cache_for_block_hash: {:?} {:p}", block_hash, cache);
    if let Ok(hash) = UInt256::from_const(block_hash) {
        (*cache).remove_quorum_members(&hash);
    }
}

/// Remove quorum snapshot from cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_clear_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_clear_cache: {:p}", cache);
    (*cache).clear();
}



/// Destroys anonymous internal holder for UInt256
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_block_hash(block_hash: *mut [u8; 32]) {
    ferment_interfaces::unbox_any(block_hash);
}

/// Destroys anonymous internal holder for UInt256
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_byte_array(data: *const u8, len: usize) {
    ferment_interfaces::unbox_vec_ptr(data as *mut u8, len);
}

/// # Safety
/// Destroys types::MNListDiffResult
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_masternode_list(list: *mut types::MasternodeList) {
    ferment_interfaces::unbox_any(list);
}

/// Destroys types::MNListDiffResult
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_mnlistdiff_result(result: *mut types::MNListDiffResult) {
    ferment_interfaces::unbox_any(result);
}

/// Destroys types::LLMQRotationInfoResult
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_qr_info_result(result: *mut types::QRInfoResult) {
    ferment_interfaces::unbox_any(result);
}

/// Destroys types::LLMQSnapshot
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_llmq_snapshot(result: *mut types::LLMQSnapshot) {
    ferment_interfaces::unbox_any(result);
}

// Here we have temporary replacement for DSKey from the DashSync
/// Destroys rust-allocated string
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = CString::from_raw(ptr);
}

/// Destroys UInt160
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_uint160(ptr: *mut [u8; 20]) {
    ferment_interfaces::unbox_any(ptr);
}

