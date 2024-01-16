use core::slice;
use std::io::Cursor;
use std::ffi::c_void;

use dash_spv_coinjoin::messages;
use dash_spv_coinjoin::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use dash_spv_coinjoin::coinjoin::CoinJoin;
use dash_spv_coinjoin::callbacks::{GetInputValueByPrevoutHash, HasChainLock, DestroyInputValue, GetWalletTransaction, DestroyWalletTransaction, IsMineInput};
use dash_spv_coinjoin::messages::transaction_outpoint::TransactionOutPoint;
use dash_spv_coinjoin::models::CoinJoinClientOptions;
use dash_spv_coinjoin::wallet_ex::WalletEx;
use dash_spv_masternode_processor::consensus::Decodable;
use dash_spv_masternode_processor::crypto::UInt256;
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
pub unsafe extern "C" fn register_wallet_ex(
    options_ptr: *mut CoinJoinClientOptions,
    get_wallet_transaction: GetWalletTransaction,
    destroy_wallet_transaction: DestroyWalletTransaction,
    is_mine: IsMineInput,
    context: *const c_void
) -> *mut WalletEx {
    let options: CoinJoinClientOptions = std::ptr::read(options_ptr);
    let wallet_ex = WalletEx::new(context, options, get_wallet_transaction, destroy_wallet_transaction, is_mine);
    println!("[RUST] register_wallet_ex: {:?}", wallet_ex);
    boxed(wallet_ex)
}

#[no_mangle]
pub unsafe extern "C" fn unregister_coinjoin(coinjoin: *mut CoinJoin) {
    println!("[RUST] 💀 unregister_coinjoin: {:?}", coinjoin);
    let unboxed = unbox_any(coinjoin);
}

#[no_mangle]
pub unsafe extern "C" fn call_coinjoin(
    coinjoin: *mut CoinJoin,
    tx: *mut Transaction,
    context: *const c_void
) -> bool {
    println!("[RUST] call coinjoin with tx: {:?}", tx);
    return (*coinjoin).is_collateral_valid(&(*tx).decode(), true);
}

#[no_mangle]
pub unsafe extern "C" fn call_wallet_ex(
    wallet_ex: *mut WalletEx,
    prevout_hash: *mut [u8; 32],
    index: u32,
) -> i32 {
    println!("[RUST] call wallet_ex");
    return (*wallet_ex).get_real_outpoint_coinjoin_rounds(TransactionOutPoint::new(UInt256(*(prevout_hash)), index), 0);
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