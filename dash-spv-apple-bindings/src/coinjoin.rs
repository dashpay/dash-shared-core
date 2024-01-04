use core::slice;
use std::io::Cursor;
use std::ffi::c_void;

use dash_spv_coinjoin::messages;
use dash_spv_coinjoin::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use dash_spv_coinjoin::coinjoin::CoinJoin;
use dash_spv_coinjoin::callbacks::{GetInputValueByPrevoutHash, HasChainLock, DestroyInputValue};
use dash_spv_masternode_processor::consensus::Decodable;
use dash_spv_masternode_processor::ffi::boxer::boxed;
use dash_spv_masternode_processor::ffi::unboxer::unbox_any;
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::types::Transaction;

#[no_mangle]
pub unsafe extern "C" fn register_coinjoin(
    get_input_value_by_prevout_hash: GetInputValueByPrevoutHash,
    has_chain_lock: HasChainLock,
    destroy_input_value: DestroyInputValue,
    context: *const c_void
) -> *mut CoinJoin {
    let coinjoin = CoinJoin::new(
        get_input_value_by_prevout_hash,
        has_chain_lock,
        destroy_input_value,
        context
    );
    println!("[RUST] register_coinjoin: {:?}", coinjoin);
    boxed(coinjoin)
}

#[no_mangle]
pub unsafe extern "C" fn unregister_coinjoin(coinjoin: *mut CoinJoin) {
    println!("[RUST] 💀 unregister_coinjoin: {:?}", coinjoin);
    let unboxed = unbox_any(coinjoin);
}

#[no_mangle]
pub unsafe extern "C" fn call_coinjoin(
    coin_join: *mut CoinJoin,
    tx: *mut Transaction,
    context: *const c_void
) -> bool {
    println!("[RUST] call coinjoin with tx: {:?}", tx);
    return (*coin_join).is_collateral_valid(&(*tx).decode(), true);
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_accept_message(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinAcceptMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinAcceptMessage::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_broadcast_tx(
    message: *const u8,
    message_length: usize
) -> *mut CoinJoinBroadcastTx {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = CoinJoinBroadcastTx::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_complete_message(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinCompleteMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinCompleteMessage::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_entry(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinEntry {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinEntry::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_final_transaction(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinFinalTransaction {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinFinalTransaction::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_queue_message(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinQueueMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinQueueMessage::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_signed_inputs(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinSignedInputs {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinSignedInputs::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_status_update(
    message: *const u8,
    message_length: usize
) -> *mut messages::CoinJoinStatusUpdate {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}

#[no_mangle]
pub unsafe extern "C" fn process_send_coinjoin_queue(
    message: *const u8,
    message_length: usize
) -> *mut messages::SendCoinJoinQueue {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    let result = messages::SendCoinJoinQueue::consensus_decode(&mut cursor).unwrap();

    boxed(result)
}