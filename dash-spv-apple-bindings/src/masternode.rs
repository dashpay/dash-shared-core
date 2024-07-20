use std::slice;
use dash_spv_masternode_processor::models;
use dash_spv_masternode_processor::chain::common::{ChainType, IHaveChainSettings, LLMQType};
use dash_spv_masternode_processor::consensus::encode;
use dash_spv_masternode_processor::crypto::byte_util::{BytesDecodable, ConstDecodable, UInt256, UInt768};
use dash_spv_masternode_processor::models::{LLMQModifierType, LLMQVerificationContext};
use dash_spv_masternode_processor::processing::{MasternodeProcessor, MasternodeProcessorCache, ProcessingError};
use crate::ffi::{common::ByteArray, from::FromFFI, to::ToFFI};
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
    let message: &[u8] = slice::from_raw_parts(message_arr, message_length);
    let result = process_mnlist_diff(&processor, message, is_from_snapshot, protocol_version, cache)
        .map_or(std::ptr::null_mut(), ferment_interfaces::boxed);
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
    println!("process_qrinfo_from_message -> {:?} {:p} {:p} {:p}", instant, processor, cache, context);
    process_qr_info(&processor, message, is_from_snapshot, protocol_version, is_rotated_quorums_presented, cache)
        .map_or(std::ptr::null_mut(), |result | {
            println!("process_qrinfo_from_message <- {:?} ms", instant.elapsed().as_millis());
            ferment_interfaces::boxed(result)
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
pub unsafe extern "C" fn validate_masternode_list(list: *const types::MasternodeList, quorum: *const types::LLMQEntry, block_height: u32, chain_type: ChainType, best_cl_signature: *const u8) -> bool {
    let list = (*list).decode();
    let mut quorum = (*quorum).decode();
    let payload_validation_status = quorum.validate_payload();
    if !payload_validation_status.is_ok() {
        return false;
    }
    let quorum_modifier_type = if let Ok(best_cl_signature) = UInt768::from_const(best_cl_signature) {
        LLMQModifierType::CoreV20(quorum.llmq_type, block_height - 8, best_cl_signature)
    } else {
        LLMQModifierType::PreCoreV20(quorum.llmq_type, quorum.llmq_hash)
    };
    let valid_masternodes = quorum.valid_masternodes(chain_type, list.masternodes, block_height, quorum_modifier_type);
    return quorum.validate(valid_masternodes, block_height).is_not_critical();
}

/// quorum_hash: u256
/// # Safety
#[no_mangle]
pub extern "C" fn quorum_build_llmq_hash(llmq_type: LLMQType, quorum_hash: *const u8) -> ByteArray {
    LLMQModifierType::PreCoreV20(llmq_type, UInt256::from_const(quorum_hash).unwrap())
        .build_llmq_hash()
        .into()
}

/// height: u32
/// best_cl_signature: Option<u768>
/// # Safety
#[no_mangle]
pub extern "C" fn quorum_build_llmq_hash_v20(llmq_type: LLMQType, height: u32, best_cl_signature: *const u8) -> ByteArray {
    LLMQModifierType::CoreV20(llmq_type, height, UInt768::from_const(best_cl_signature).unwrap())
        .build_llmq_hash()
        .into()
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
pub extern "C" fn quorum_should_process_type_for_chain(llmq_type: LLMQType, chain_type: ChainType) -> bool {
    chain_type.should_process_llmq_of_type(llmq_type)
}


/// Helper functions
pub fn get_list_diff_result(
    processor: &MasternodeProcessor,
    base_list: Option<models::MasternodeList>,
    list_diff: models::MNListDiff,
    verification_context: LLMQVerificationContext,
    cache: &mut MasternodeProcessorCache,
) -> types::MNListDiffResult {
    let result = processor.get_list_diff_result(base_list, list_diff, verification_context, cache);
    // println!("get_list_diff_result: {:#?}", result);
    result.into()
}

pub fn get_list_diff_result_with_base_lookup(
    processor: &MasternodeProcessor,
    list_diff: models::MNListDiff,
    verification_context: LLMQVerificationContext,
    cache: &mut MasternodeProcessorCache,
) -> types::MNListDiffResult {
    let base_block_hash = list_diff.base_block_hash;
    let base_list = processor.provider.find_masternode_list(
        base_block_hash,
        &cache.mn_lists,
        &mut cache.needed_masternode_lists,
    );
    get_list_diff_result(&processor, base_list.ok(), list_diff, verification_context, cache)
}

pub fn process_mnlist_diff(processor: &MasternodeProcessor, message: &[u8], is_from_snapshot: bool, protocol_version: u32, cache: &mut MasternodeProcessorCache) -> Result<types::MNListDiffResult, ProcessingError> {
    match processor.read_list_diff_from_message(message, &mut 0, protocol_version) {
        Ok(list_diff) => {
            if !is_from_snapshot {
                processor.provider.should_process_diff_with_range(list_diff.base_block_hash, list_diff.block_hash)?;
            }
            Ok(get_list_diff_result_with_base_lookup(processor, list_diff, LLMQVerificationContext::MNListDiff, cache))
        },
        Err(err) => Err(ProcessingError::from(err))
    }
}

pub fn process_qr_info(processor: &MasternodeProcessor, message: &[u8], is_from_snapshot: bool, protocol_version: u32, is_rotated_quorums_presented: bool, cache: &mut MasternodeProcessorCache) -> Result<types::QRInfoResult, ProcessingError> {
    let mut process_list_diff = |list_diff: models::MNListDiff, verification_context: LLMQVerificationContext|
        get_list_diff_result_with_base_lookup(&processor, list_diff, verification_context, cache);
    let read_list_diff = |offset: &mut usize|
        processor.read_list_diff_from_message(message, offset, protocol_version).map_err(ProcessingError::from);
    let read_snapshot = |offset: &mut usize|
        models::LLMQSnapshot::from_bytes(message, offset).map_err(ProcessingError::from);
    let read_var_int = |offset: &mut usize|
        encode::VarInt::from_bytes(message, offset).map_err(ProcessingError::from);
    let mut get_list_diff_result = |list_diff: models::MNListDiff, verification_context: LLMQVerificationContext|
        ferment_interfaces::boxed(process_list_diff(list_diff, verification_context));

    let offset = &mut 0;
    let snapshot_at_h_c = read_snapshot(offset)?;
    let snapshot_at_h_2c = read_snapshot(offset)?;
    let snapshot_at_h_3c = read_snapshot(offset)?;
    let diff_tip = read_list_diff(offset)?;
    if !is_from_snapshot {
        processor.provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash)?;
    }
    let diff_h = read_list_diff(offset)?;
    let diff_h_c = read_list_diff(offset)?;
    let diff_h_2c = read_list_diff(offset)?;
    let diff_h_3c = read_list_diff(offset)?;
    let extra_share = message[*offset] > 0;
    *offset += 1;
    let (snapshot_at_h_4c, diff_h_4c) = if extra_share {
        let snapshot_at_h_4c = read_snapshot(offset)?;
        let diff_h_4c = read_list_diff(offset)?;
        (Some(snapshot_at_h_4c), Some(diff_h_4c))
    } else {
        (None, None)
    };
    processor.provider.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
    processor.provider.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
    processor.provider.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
    if extra_share {
        processor.provider.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.clone().unwrap());
    }

    let last_quorum_per_index_count = read_var_int(offset)?.0 as usize;
    let mut last_quorum_per_index_vec: Vec<*mut types::LLMQEntry> =
        Vec::with_capacity(last_quorum_per_index_count);
    for _i in 0..last_quorum_per_index_count {
        let quorum = models::LLMQEntry::from_bytes(message, offset).map_err(ProcessingError::from)?;
        last_quorum_per_index_vec.push(ferment_interfaces::boxed(quorum.encode()));
    }
    let quorum_snapshot_list_count = read_var_int(offset)?.0 as usize;
    let mut quorum_snapshot_list_vec: Vec<*mut types::LLMQSnapshot> =
        Vec::with_capacity(quorum_snapshot_list_count);
    let mut snapshots: Vec<models::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
    for _i in 0..quorum_snapshot_list_count {
        snapshots.push(read_snapshot(offset)?);
    }
    let mn_list_diff_list_count = read_var_int(offset)?.0 as usize;
    let mut mn_list_diff_list_vec: Vec<*mut types::MNListDiffResult> =
        Vec::with_capacity(mn_list_diff_list_count);
    assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
    for i in 0..mn_list_diff_list_count {
        let list_diff = read_list_diff(offset)?;
        let block_hash = list_diff.block_hash;
        mn_list_diff_list_vec.push(get_list_diff_result(list_diff, LLMQVerificationContext::None));
        let snapshot = snapshots.get(i).unwrap();
        quorum_snapshot_list_vec.push(ferment_interfaces::boxed(snapshot.encode()));
        processor.provider.save_snapshot(block_hash, snapshot.clone());
    }

    let result_at_h_4c = if extra_share {
        get_list_diff_result(diff_h_4c.unwrap(), LLMQVerificationContext::None)
    } else {
        std::ptr::null_mut()
    };
    let result_at_h_3c = get_list_diff_result(diff_h_3c, LLMQVerificationContext::None);
    let result_at_h_2c = get_list_diff_result(diff_h_2c, LLMQVerificationContext::None);
    let result_at_h_c = get_list_diff_result(diff_h_c, LLMQVerificationContext::None);
    let result_at_h = get_list_diff_result(diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented));
    let result_at_tip = get_list_diff_result(diff_tip, LLMQVerificationContext::None);
    let result = types::QRInfoResult {
        error_status: ProcessingError::None,
        result_at_tip,
        result_at_h,
        result_at_h_c,
        result_at_h_2c,
        result_at_h_3c,
        result_at_h_4c,
        snapshot_at_h_c: ferment_interfaces::boxed(snapshot_at_h_c.encode()),
        snapshot_at_h_2c: ferment_interfaces::boxed(snapshot_at_h_2c.encode()),
        snapshot_at_h_3c: ferment_interfaces::boxed(snapshot_at_h_3c.encode()),
        snapshot_at_h_4c: if extra_share {
            ferment_interfaces::boxed(snapshot_at_h_4c.unwrap().encode())
        } else {
            std::ptr::null_mut()
        },
        extra_share,
        last_quorum_per_index: ferment_interfaces::boxed_vec(last_quorum_per_index_vec),
        last_quorum_per_index_count,
        quorum_snapshot_list: ferment_interfaces::boxed_vec(quorum_snapshot_list_vec),
        quorum_snapshot_list_count,
        mn_list_diff_list: ferment_interfaces::boxed_vec(mn_list_diff_list_vec),
        mn_list_diff_list_count,
    };
    Ok(result)
}