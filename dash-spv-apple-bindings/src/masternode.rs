use std::slice;
use dash_spv_masternode_processor::{models, ok_or_return_processing_error};
use dash_spv_masternode_processor::chain::common::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_masternode_processor::consensus::encode;
use dash_spv_masternode_processor::crypto::{UInt256, byte_util::ConstDecodable};
use dash_spv_masternode_processor::crypto::byte_util::BytesDecodable;
use dash_spv_masternode_processor::ffi::ByteArray;
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache, ProcessingError};
use crate::ffi::{from::FromFFI, to::ToFFI};
use crate::types;

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
    let result = process_mnlist_diff(&processor, message, is_from_snapshot, protocol_version, cache)
        .map_or(std::ptr::null_mut(), rs_ffi_interfaces::boxed);
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
    process_qr_info(&processor, message, is_from_snapshot, protocol_version, is_rotated_quorums_presented, cache)
        .map_or(std::ptr::null_mut(), |result | {
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


/// Helper functions
pub fn get_list_diff_result(
    processor: &MasternodeProcessor,
    base_list: Option<models::MasternodeList>,
    list_diff: models::MNListDiff,
    should_process_quorums: bool,
    is_dip_0024: bool,
    is_rotated_quorums_presented: bool,
    cache: &mut MasternodeProcessorCache,
) -> types::MNListDiffResult {
    let result = processor.get_list_diff_result_internal(base_list, list_diff, should_process_quorums, is_dip_0024, is_rotated_quorums_presented, cache);
    // println!("get_list_diff_result: {:#?}", result);
    result.into()
}

pub fn get_list_diff_result_with_base_lookup(
    processor: &MasternodeProcessor,
    list_diff: models::MNListDiff,
    should_process_quorums: bool,
    is_dip_0024: bool,
    is_rotated_quorums_presented: bool,
    cache: &mut MasternodeProcessorCache,
) -> types::MNListDiffResult {
    let base_block_hash = list_diff.base_block_hash;
    let base_list = processor.provider.find_masternode_list(
        base_block_hash,
        &cache.mn_lists,
        &mut cache.needed_masternode_lists,
    );
    get_list_diff_result(&processor, base_list.ok(), list_diff, should_process_quorums, is_dip_0024, is_rotated_quorums_presented, cache)
}

pub fn process_mnlist_diff(processor: &MasternodeProcessor, message: &[u8], is_from_snapshot: bool, protocol_version: u32, cache: &mut MasternodeProcessorCache) -> Result<types::MNListDiffResult, ProcessingError> {
    match processor.read_list_diff_from_message(message, &mut 0, protocol_version) {
        Ok(list_diff) => {
            if !is_from_snapshot {
                ok_or_return_processing_error!(processor.provider.should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash));
            }
            Ok(get_list_diff_result_with_base_lookup(processor, list_diff, true, false, false, cache))
        },
        Err(err) => Err(ProcessingError::from(err))
    }
}

pub fn process_qr_info(processor: &MasternodeProcessor, message: &[u8], is_from_snapshot: bool, protocol_version: u32, is_rotated_quorums_presented: bool, cache: &mut MasternodeProcessorCache) -> Result<types::QRInfoResult, ProcessingError> {
    let mut process_list_diff = |list_diff: models::MNListDiff, should_process_quorums: bool|
        get_list_diff_result_with_base_lookup(&processor, list_diff, should_process_quorums, true, is_rotated_quorums_presented, cache);
    let read_list_diff = |offset: &mut usize|
        processor.read_list_diff_from_message(message, offset, protocol_version);
    let read_snapshot = |offset: &mut usize|
        models::LLMQSnapshot::from_bytes(message, offset);
    let read_var_int = |offset: &mut usize|
        encode::VarInt::from_bytes(message, offset);
    let mut get_list_diff_result = |list_diff: models::MNListDiff, verify_quorums: bool|
        rs_ffi_interfaces::boxed(process_list_diff(list_diff, verify_quorums));

    let offset = &mut 0;
    let snapshot_at_h_c = ok_or_return_processing_error!(read_snapshot(offset));
    let snapshot_at_h_2c = ok_or_return_processing_error!(read_snapshot(offset));
    let snapshot_at_h_3c = ok_or_return_processing_error!(read_snapshot(offset));
    let diff_tip = ok_or_return_processing_error!(read_list_diff(offset));
    if !is_from_snapshot {
        ok_or_return_processing_error!(processor.provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash));
    }
    let diff_h = ok_or_return_processing_error!(read_list_diff(offset));
    let diff_h_c = ok_or_return_processing_error!(read_list_diff(offset));
    let diff_h_2c = ok_or_return_processing_error!(read_list_diff(offset));
    let diff_h_3c = ok_or_return_processing_error!(read_list_diff(offset));
    let extra_share = message[*offset] > 0;
    *offset += 1;
    // let extra_share = message.read_with::<bool>(offset, ()).unwrap_or(false);
    let (snapshot_at_h_4c, diff_h_4c) = if extra_share {
        let snapshot_at_h_4c = ok_or_return_processing_error!(read_snapshot(offset));
        let diff_h_4c = ok_or_return_processing_error!(read_list_diff(offset));
        (Some(snapshot_at_h_4c), Some(diff_h_4c))
    } else {
        (None, None)
    };
    #[cfg(feature = "generate-dashj-tests")]
    crate::util::java::save_snapshot_to_json(&snapshot_at_h_c, processor.provider.lookup_block_height_by_hash(block_hash));
    processor.provider.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
    #[cfg(feature = "generate-dashj-tests")]
    crate::util::java::save_snapshot_to_json(&snapshot_at_h_2c, processor.provider.lookup_block_height_by_hash(block_hash));
    processor.provider.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
    #[cfg(feature = "generate-dashj-tests")]
    crate::util::java::save_snapshot_to_json(&snapshot_at_h_3c, processor.provider.lookup_block_height_by_hash(block_hash));
    processor.provider.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
    if extra_share {
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(snapshot_at_h_4c.as_ref().unwrap(), processor.provider.lookup_block_height_by_hash(block_hash));
        processor.provider.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.clone().unwrap());
    }

    let last_quorum_per_index_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
    let mut last_quorum_per_index_vec: Vec<*mut types::LLMQEntry> =
        Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        let quorum = ok_or_return_processing_error!(models::LLMQEntry::from_bytes(message, offset));
        last_quorum_per_index_vec.push(rs_ffi_interfaces::boxed(quorum.encode()));
    }
    let quorum_snapshot_list_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
    let mut quorum_snapshot_list_vec: Vec<*mut types::LLMQSnapshot> =
        Vec::with_capacity(quorum_snapshot_list_count);
    let mut snapshots: Vec<models::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        let snapshot = ok_or_return_processing_error!(read_snapshot(offset));
        snapshots.push(snapshot);
    }
    let mn_list_diff_list_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
    let mut mn_list_diff_list_vec: Vec<*mut types::MNListDiffResult> =
        Vec::with_capacity(mn_list_diff_list_count);
    assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
    for i in 0..mn_list_diff_list_count {
        let list_diff = ok_or_return_processing_error!(read_list_diff(offset));
        let block_hash = list_diff.block_hash;
        mn_list_diff_list_vec.push(get_list_diff_result(list_diff, false));
        let snapshot = snapshots.get(i).unwrap();
        quorum_snapshot_list_vec.push(rs_ffi_interfaces::boxed(snapshot.encode()));
        processor.provider.save_snapshot(block_hash, snapshot.clone());
    }

    let result_at_h_4c = if extra_share {
        get_list_diff_result(diff_h_4c.unwrap(), false)
    } else {
        std::ptr::null_mut()
    };
    let result_at_h_3c = get_list_diff_result(diff_h_3c, false);
    let result_at_h_2c = get_list_diff_result(diff_h_2c, false);
    let result_at_h_c = get_list_diff_result(diff_h_c, false);
    let result_at_h = get_list_diff_result(diff_h, true);
    let result_at_tip = get_list_diff_result(diff_tip, false);
    let result = types::QRInfoResult {
        error_status: ProcessingError::None,
        result_at_tip,
        result_at_h,
        result_at_h_c,
        result_at_h_2c,
        result_at_h_3c,
        result_at_h_4c,
        snapshot_at_h_c: rs_ffi_interfaces::boxed(snapshot_at_h_c.encode()),
        snapshot_at_h_2c: rs_ffi_interfaces::boxed(snapshot_at_h_2c.encode()),
        snapshot_at_h_3c: rs_ffi_interfaces::boxed(snapshot_at_h_3c.encode()),
        snapshot_at_h_4c: if extra_share {
            rs_ffi_interfaces::boxed(snapshot_at_h_4c.unwrap().encode())
        } else {
            std::ptr::null_mut()
        },
        extra_share,
        last_quorum_per_index: rs_ffi_interfaces::boxed_vec(last_quorum_per_index_vec),
        last_quorum_per_index_count,
        quorum_snapshot_list: rs_ffi_interfaces::boxed_vec(quorum_snapshot_list_vec),
        quorum_snapshot_list_count,
        mn_list_diff_list: rs_ffi_interfaces::boxed_vec(mn_list_diff_list_vec),
        mn_list_diff_list_count,
    };
    Ok(result)
}