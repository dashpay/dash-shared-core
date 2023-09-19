use std::ptr::null_mut;
use std::slice;
use dash_spv_masternode_processor::{models, types};
use dash_spv_masternode_processor::chain::common::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_masternode_processor::crypto::{UInt256, byte_util::ConstDecodable};
use dash_spv_masternode_processor::ffi::{ByteArray, from::FromFFI};
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache};


/// Read and process message received as a response for 'GETMNLISTDIFF' call
/// Here we calculate quorums according to Core v0.17
/// See https://github.com/dashpay/dips/blob/master/dip-0004.md
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn process_mnlistdiff_from_message(
    message_arr: *const u8,
    message_length: usize,
    chain_type: ChainType,
    use_insight_as_backup: bool,
    is_from_snapshot: bool,
    protocol_version: u32,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> *mut types::MNListDiffResult {
    let instant = std::time::Instant::now();
    let processor = &mut *processor;
    let cache = &mut *cache;
    println!("process_mnlistdiff_from_message -> {:?} {:p} {:p} {:p}", instant, processor, cache, context);
    // processor.provider = context;
    // processor.use_insight_as_backup = use_insight_as_backup;
    // processor.chain_type = chain_type;

    let message: &[u8] = slice::from_raw_parts(message_arr, message_length);
    let result = processor.process_mnlist_diff(message, is_from_snapshot, protocol_version, cache)
        .map_or(null_mut(), rs_ffi_interfaces::boxed);
    println!("process_mnlistdiff_from_message <- {:?} ms", instant.elapsed().as_millis());
    result
}

/// Here we read & calculate quorums according to Core v0.18
/// See https://github.com/dashpay/dips/blob/master/dip-0024.md
/// The reason behind we have multiple methods for this is that:
/// in objc we need 2 separate calls to incorporate additional logics between reading and processing
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn process_qrinfo_from_message(
    message: *const u8,
    message_length: usize,
    chain_type: ChainType,
    use_insight_as_backup: bool,
    is_from_snapshot: bool,
    is_rotated_quorums_presented: bool,
    protocol_version: u32,
    processor: *mut MasternodeProcessor,
    cache: *mut MasternodeProcessorCache,
    context: *const std::ffi::c_void,
) -> *mut types::QRInfoResult {
    let instant = std::time::Instant::now();
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let processor = &mut *processor;
    let cache = &mut *cache;
    // processor.opaque_context = context;
    // processor.use_insight_as_backup = use_insight_as_backup;
    // processor.chain_type = chain_type;
    println!("process_qrinfo_from_message -> {:?} {:p} {:p} {:p}", instant, processor, cache, context);
    processor.process_qr_info(message, is_from_snapshot, protocol_version, is_rotated_quorums_presented, cache)
        .map_or(null_mut(), |result | {
            #[cfg(feature = "generate-dashj-tests")]
            crate::util::java::generate_qr_state_test_file_json(chain_type, result);
            println!("process_qrinfo_from_message <- {:?} ms", instant.elapsed().as_millis());
            rs_ffi_interfaces::boxed(result)
        })
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_cache_masternode_list(block_hash: *const u8, list: *const types::MasternodeList, cache: *mut MasternodeProcessorCache) {
    (&mut *cache).add_masternode_list(
        UInt256::from_const(block_hash).unwrap(),
        (*list).decode());
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn validate_masternode_list(list: *const types::MasternodeList, quorum: *const types::LLMQEntry, block_height: u32, chain_type: ChainType) -> bool {
    let list = (*list).decode();
    let mut quorum = (*quorum).decode();
    let is_valid_payload = quorum.validate_payload();
    if !is_valid_payload {
        return false;
    }
    let hpmn_only = quorum.llmq_type == chain_type.platform_type() && !quorum.version.use_bls_legacy();
    let valid_masternodes = models::MasternodeList::get_masternodes_for_quorum(quorum.llmq_type, list.masternodes, quorum.llmq_quorum_hash(), block_height, hpmn_only);
    return quorum.validate(valid_masternodes, block_height);
}


/// # Safety
#[no_mangle]
pub extern "C" fn quorum_size_for_type(llmq_type: LLMQType) -> u32 {
    llmq_type.size()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_threshold_for_type(llmq_type: LLMQType) -> u32 {
    llmq_type.threshold()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_build_llmq_hash(llmq_type: LLMQType, quorum_hash: *const u8) -> ByteArray {
    models::LLMQEntry::build_llmq_quorum_hash(llmq_type, UInt256::from_const(quorum_hash).unwrap()).into()
}

/// # Safety
#[no_mangle]
pub extern "C" fn masternode_hash_confirmed_hash(confirmed_hash: *const u8, pro_reg_tx_hash: *const u8) -> ByteArray {
    let confirmed_hash = UInt256::from_const(confirmed_hash).unwrap_or(UInt256::MIN);
    let pro_reg_tx_hash = UInt256::from_const(pro_reg_tx_hash).unwrap_or(UInt256::MIN);
    models::MasternodeEntry::hash_confirmed_hash(confirmed_hash, pro_reg_tx_hash).into()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_type_for_is_locks(chain_type: ChainType) -> LLMQType {
    chain_type.is_llmq_type()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_type_for_isd_locks(chain_type: ChainType) -> LLMQType {
    chain_type.isd_llmq_type()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_type_for_chain_locks(chain_type: ChainType) -> LLMQType {
    chain_type.chain_locks_type()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_type_for_platform(chain_type: ChainType) -> LLMQType {
    chain_type.platform_type()
}

/// # Safety
#[no_mangle]
pub extern "C" fn quorum_should_process_type_for_chain(llmq_type: LLMQType, chain_type: ChainType) -> bool {
    chain_type.should_process_llmq_of_type(llmq_type)
}
