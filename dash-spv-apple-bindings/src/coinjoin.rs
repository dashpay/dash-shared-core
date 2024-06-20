use core::slice;
use std::cell::RefCell;
use std::io::Cursor;
use std::ffi::{c_void, CStr};
use std::os::raw::c_char;
use std::rc::Rc;

use dash_spv_coinjoin::coinjoin_client_manager::CoinJoinClientManager;
use dash_spv_coinjoin::coinjoin_client_queue_manager::CoinJoinClientQueueManager;

use dash_spv_coinjoin::masternode_meta_data_manager::MasternodeMetadataManager;
use dash_spv_coinjoin::messages::coinjoin_message::CoinJoinMessage;
use dash_spv_coinjoin::{ffi, messages};
use dash_spv_coinjoin::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use dash_spv_coinjoin::coinjoin::CoinJoin;
use dash_spv_coinjoin::ffi::callbacks::{AddPendingMasternode, AvailableCoins, CommitTransaction, DestroyGatheredOutputs, DestroyInputValue, DestroyMasternode, DestroyMasternodeList, DestroySelectedCoins, DestroyWalletTransaction, DisconnectMasternode, FreshCoinJoinAddress, GetInputValueByPrevoutHash, GetMasternodeList, GetWalletTransaction, HasChainLock, InputsWithAmount, IsBlockchainSynced, IsMasternodeOrDisconnectRequested, IsMineInput, MasternodeByHash, SelectCoinsGroupedByAddresses, SendMessage, SignTransaction, ValidMasternodeCount};
use dash_spv_coinjoin::models::tx_outpoint::TxOutPoint;
use dash_spv_coinjoin::models::{Balance, CoinJoinClientOptions};
use dash_spv_coinjoin::wallet_ex::WalletEx;
use dash_spv_masternode_processor::common::SocketAddress;
use dash_spv_masternode_processor::consensus::Decodable;
use ferment_interfaces::{boxed, unbox_any};
use dash_spv_masternode_processor::crypto::{UInt128, UInt256};
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::crypto::byte_util::ConstDecodable;
use dash_spv_masternode_processor::ffi::boxer::boxed;
use dash_spv_masternode_processor::ffi::unboxer::unbox_any;
use dash_spv_masternode_processor::ffi::ByteArray;
use dash_spv_masternode_processor::types;

#[no_mangle]
pub unsafe extern "C" fn register_wallet_ex(
    context: *const c_void,
    options_ptr: *mut CoinJoinClientOptions,
    get_wallet_transaction: GetWalletTransaction,
    sign_transaction: SignTransaction,
    destroy_transaction: DestroyWalletTransaction,
    is_mine: IsMineInput,
    commit_transaction: CommitTransaction,
    is_synced: IsBlockchainSynced,
    fresh_coinjoin_key: FreshCoinJoinAddress,
    count_inputs_with_amount: InputsWithAmount,
    available_coins: AvailableCoins,
    destroy_gathered_outputs: DestroyGatheredOutputs,
    selected_coins: SelectCoinsGroupedByAddresses,
    destroy_selected_coins: DestroySelectedCoins,
    is_masternode_or_disconnect_requested: IsMasternodeOrDisconnectRequested,
    disconnect_masternode: DisconnectMasternode,
    send_message: SendMessage,
    add_pending_masternode: AddPendingMasternode
) -> *mut WalletEx {
    let wallet_ex =  WalletEx::new(
        context, 
        std::ptr::read(options_ptr), 
        get_wallet_transaction, 
        sign_transaction,
        destroy_transaction, 
        is_mine, 
        available_coins, 
        destroy_gathered_outputs,
        selected_coins, 
        destroy_selected_coins,
        count_inputs_with_amount,
        fresh_coinjoin_key,
        commit_transaction,
        is_synced,
        is_masternode_or_disconnect_requested,
        disconnect_masternode,
        send_message,
        add_pending_masternode
    );

    println!("[RUST] CoinJoin: register_wallet_ex");
    return boxed(wallet_ex);
}

#[no_mangle]
pub unsafe extern "C" fn register_client_manager(
    context: *const c_void,
    wallet_ex_ptr: *mut WalletEx,
    options_ptr: *mut CoinJoinClientOptions,
    get_masternode_list: GetMasternodeList,
    destroy_mn_list: DestroyMasternodeList,
    get_input_value_by_prevout_hash: GetInputValueByPrevoutHash,
    has_chain_lock: HasChainLock,
    destroy_input_value: DestroyInputValue
) -> *mut CoinJoinClientManager {
    let coinjoin = CoinJoin::new(
        get_input_value_by_prevout_hash,
        has_chain_lock,
        destroy_input_value,
        context
    );

    let client_manager = CoinJoinClientManager::new(
        Rc::new(RefCell::new(std::ptr::read(wallet_ex_ptr))),
        Rc::new(RefCell::new(coinjoin)),
        std::ptr::read(options_ptr), 
        get_masternode_list,
        destroy_mn_list,
        context
    );
    println!("[RUST] CoinJoin: register_client_manager");
    boxed(client_manager)
}

#[no_mangle]
pub unsafe extern "C" fn add_client_queue_manager(
    client_manager_ptr: *mut CoinJoinClientManager,
    options_ptr: *mut CoinJoinClientOptions,
    masternode_by_hash: MasternodeByHash,
    destroy_masternode: DestroyMasternode,
    valid_mns_count: ValidMasternodeCount,
    is_synced: IsBlockchainSynced,
    context: *const c_void
) {
    let client_queue_manager = CoinJoinClientQueueManager::new(
        Rc::new(RefCell::new(std::ptr::read(client_manager_ptr))),
        MasternodeMetadataManager::new(), 
        std::ptr::read(options_ptr), 
        masternode_by_hash, 
        destroy_masternode, 
        valid_mns_count, 
        is_synced, 
        context
    );

    (*client_manager_ptr).set_client_queue_manager(Rc::new(RefCell::new(client_queue_manager)));

    println!("[RUST] CoinJoin: add_client_queue_manager");
}

#[no_mangle]
pub unsafe extern "C" fn run_client_manager( // TODO: temp method for testing
    client_manager: *mut CoinJoinClientManager,
    balance_info: Balance
) {
    (*client_manager).start_mixing();
    (*client_manager).do_maintenance(balance_info);
}

#[no_mangle]
pub unsafe extern "C" fn finish_automatic_denominating(
    manager: *mut CoinJoinClientManager
) -> bool {
    println!("[RUST] CoinJoin: session.finish_automatic_denominating");
    return (*manager).finish_automatic_denominating();
}

#[no_mangle]
pub unsafe extern "C" fn mixing_masternode_address(
    manager: *mut CoinJoinClientManager,
    client_session_id: *mut [u8; 32]
) -> *mut ffi::socket_addres::SocketAddress {
    if let Some(address) = (*manager).mixing_masternode_address(UInt256(*(client_session_id))) {
        return boxed(ffi::socket_addres::SocketAddress {
            ip_address: boxed(address.ip_address.0),
            port: address.port
        });
    } else {
        return std::ptr::null_mut();
    }
}

#[no_mangle]
pub unsafe extern "C" fn destroy_transaction(
    tx: *mut types::Transaction
) {
    println!("[RUST] CoinJoin 💀 destroy_transaction");
    let unboxed = unbox_any(tx);
}

#[no_mangle]
pub unsafe extern "C" fn destroy_socket_address(
    socket_address: *mut ffi::socket_addres::SocketAddress
) {
    println!("[RUST] CoinJoin 💀 destroy_socket_address");
    let unboxed = unbox_any(socket_address);
    let _ = unbox_any(unboxed.ip_address);
}

#[no_mangle]
pub unsafe extern "C" fn unregister_client_manager(client_manager: *mut CoinJoinClientManager) {
    println!("[RUST] CoinJoin 💀 unregister_client_manager");
    let unboxed = unbox_any(client_manager);
}

#[no_mangle]
pub unsafe extern "C" fn unregister_wallet_ex(wallet_ex_ptr: *mut WalletEx) {
    println!("[RUST] WalletEx 💀 unregister_wallet_ex: {:?}", wallet_ex_ptr);
    let _wallet_ex_rc = Rc::from_raw(wallet_ex_ptr as *mut RefCell<WalletEx>);
}

#[no_mangle]
pub unsafe extern "C" fn is_denominated_amount(
    amount: u64,
) -> bool {
    return CoinJoin::is_denominated_amount(amount);
}

#[no_mangle]
pub unsafe extern "C" fn is_collateral_amount(
    amount: u64,
) -> bool {
    return CoinJoin::is_collateral_amount(amount);
}

#[no_mangle]
pub unsafe extern "C" fn is_fully_mixed(
    wallet_ex: *mut WalletEx,
    prevout_hash: *mut [u8; 32],
    index: u32,
) -> bool {
    return (*wallet_ex).is_fully_mixed(TxOutPoint::new(UInt256(*(prevout_hash)), index));
}

#[no_mangle]
pub unsafe extern "C" fn is_locked_coin(
    wallet_ex: *mut WalletEx,
    prevout_hash: *mut [u8; 32],
    index: u32,
) -> bool {
    return (*wallet_ex).locked_coins_set.contains(&TxOutPoint::new(UInt256(*(prevout_hash)), index));
}

#[no_mangle]
pub unsafe extern "C" fn coinjoin_get_smallest_denomination() -> u64 {
    println!("[RUST] CoinJoin call coinjoin_get_smallest_denomination");
    return CoinJoin::get_smallest_denomination();
}

#[no_mangle]
pub unsafe extern "C" fn process_coinjoin_message(
    client_manager: *mut CoinJoinClientManager,
    peer_address: *const u8,
    peer_port: u16,
    message: *mut ByteArray,
    message_type: *const c_char
) {
    let c_str = unsafe { CStr::from_ptr(message_type) };
    let message = match c_str.to_str().unwrap() {
        "dssu" => CoinJoinMessage::StatusUpdate(process_coinjoin_status_update((*message).ptr, (*message).len)),
        "dsf" => CoinJoinMessage::FinalTransaction(process_coinjoin_final_transaction((*message).ptr, (*message).len)),
        "dsc" => CoinJoinMessage::Complete(process_coinjoin_complete_message((*message).ptr, (*message).len)),
        _ => panic!("Unsupported message type")
    };

    let from_peer = SocketAddress {
        ip_address: UInt128::from_const(peer_address).unwrap_or(UInt128::MIN),
        port: peer_port
    };
    
    (*client_manager).process_message(from_peer, message);
}

unsafe fn process_coinjoin_accept_message(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinAcceptMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return messages::CoinJoinAcceptMessage::consensus_decode(&mut cursor).unwrap();
}

unsafe fn process_coinjoin_broadcast_tx(
    message: *const u8,
    message_length: usize
) -> CoinJoinBroadcastTx {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return CoinJoinBroadcastTx::consensus_decode(&mut cursor).unwrap();
}

unsafe fn process_coinjoin_complete_message(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinCompleteMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return messages::CoinJoinCompleteMessage::consensus_decode(&mut cursor).unwrap();
}

unsafe fn process_coinjoin_entry(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinEntry {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    return messages::CoinJoinEntry::consensus_decode(&mut cursor).unwrap();
}

unsafe fn process_coinjoin_final_transaction(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinFinalTransaction {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return messages::CoinJoinFinalTransaction::consensus_decode(&mut cursor).unwrap();
}

unsafe fn process_coinjoin_queue_message(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinQueueMessage {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return messages::CoinJoinQueueMessage::consensus_decode(&mut cursor).unwrap();
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

unsafe fn process_coinjoin_status_update(
    message: *const u8,
    message_length: usize
) -> messages::CoinJoinStatusUpdate {
    let message: &[u8] = slice::from_raw_parts(message, message_length);
    let mut cursor = Cursor::new(message);
    
    return messages::CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();
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

#[no_mangle]
pub unsafe extern "C" fn is_waiting_for_new_block(
    client_manager: *mut CoinJoinClientManager
) -> bool {
    return (*client_manager).is_waiting_for_new_block();
}

#[no_mangle]
pub unsafe extern "C" fn is_mixing(
    client_manager: *mut CoinJoinClientManager
)-> bool {
    return (*client_manager).is_mixing;
}

#[no_mangle]
pub unsafe extern "C" fn process_ds_queue(
    client_manager: *mut CoinJoinClientManager,
    peer_address: *const u8,
    peer_port: u16,
    message: *mut ByteArray
) {
    let from_peer = SocketAddress {
        ip_address: UInt128::from_const(peer_address).unwrap_or(UInt128::MIN),
        port: peer_port
    };
    let message = process_coinjoin_queue_message((*message).ptr, (*message).len);
    (*client_manager).queue_queue_manager.as_ref().unwrap().borrow_mut().process_ds_queue(from_peer, message);
}