use std::ffi::{c_char, c_void};
use dash_spv_masternode_processor::ffi::ByteArray;
use dash_spv_masternode_processor::types::{self, MasternodeEntry};
use crate::ffi::selected_coins::SelectedCoins;
use crate::messages::{PoolMessage, PoolState, PoolStatus};
use crate::wallet_ex::WalletEx;

use super::coin_control::CoinControl;
use super::coinjoin_keys::CoinJoinKeys;
use super::gathered_outputs::GatheredOutputs;
use super::input_value::InputValue;
use super::recepient::Recipient;

pub type GetInputValueByPrevoutHash = unsafe extern "C" fn(
    prevout_hash: *mut [u8; 32],
    index: u32,
    context: *const c_void,
) -> *mut InputValue;

pub type HasChainLock = unsafe extern "C" fn(
    block: *mut types::Block,
    context: *const c_void,
) -> bool;

pub type DestroyInputValue = unsafe extern "C" fn(
    input_value: *mut InputValue,
);

pub type GetWalletTransaction = unsafe extern "C" fn(
    hash: *mut [u8; 32],
    context: *const c_void,
) -> *mut types::Transaction;

pub type DestroyWalletTransaction = unsafe extern "C" fn(
    input_value: *mut types::Transaction,
);

pub type SignTransaction = unsafe extern "C" fn(
    transaction: *mut types::Transaction,
    anyone_can_pay: bool,
    context: *const c_void
) -> *mut types::Transaction;

pub type IsMineInput = unsafe extern "C" fn(
    prevout_hash: *mut [u8; 32],
    index: u32,
    context: *const c_void,
) -> bool;

pub type AvailableCoins = unsafe extern "C" fn(
    only_safe: bool,
    coin_control: *mut CoinControl,
    wallet_ex: &mut WalletEx,
    context: *const c_void,
) -> *mut GatheredOutputs;

pub type DestroyGatheredOutputs = unsafe extern "C" fn(
    gathered_outputs: *mut GatheredOutputs,
);

pub type SelectCoinsGroupedByAddresses = unsafe extern "C" fn(
    skip_denominated: bool,
    anonymizable: bool,
    skip_unconfirmed: bool,
    max_oupoints_per_address: i32,
    wallet_ex: &mut WalletEx,
    context: *const c_void,
) -> *mut SelectedCoins;

pub type DestroySelectedCoins = unsafe extern "C" fn(
    selected_coins: *mut SelectedCoins,
);

pub type InputsWithAmount = unsafe extern "C" fn(
    amount: u64,
    context: *const c_void,
) -> u32;

pub type FreshCoinJoinAddress = unsafe extern "C" fn(
    internal: bool,
    context: *const c_void,
) -> ByteArray;

pub type CommitTransaction = unsafe extern "C" fn(
    items: *mut *mut Recipient,
    item_count: usize,
    coin_control: *mut CoinControl,
    is_denominating: bool,
    client_session_id: *mut [u8; 32],
    context: *const c_void
) -> bool;

pub type MasternodeByHash = unsafe extern "C" fn(
    address: *mut [u8; 32],
    context: *const c_void,
) -> *mut MasternodeEntry;

pub type DestroyMasternode = unsafe extern "C" fn(
    selected_coins: *mut MasternodeEntry,
);

pub type ValidMasternodeCount = unsafe extern "C" fn(
    context: *const c_void,
) -> u64;

pub type IsBlockchainSynced = unsafe extern "C" fn(
    context: *const c_void,
) -> bool;

pub type GetMasternodeList = unsafe extern "C" fn(
    context: *const c_void,
) -> *mut types::MasternodeList;

pub type DestroyMasternodeList = unsafe extern "C" fn(
    mn_list: *mut types::MasternodeList,
);

pub type IsMasternodeOrDisconnectRequested = unsafe extern "C" fn(
    ip_address: *mut [u8; 16],
    port: u16,
    context: *const c_void
) -> bool;

pub type DisconnectMasternode = unsafe extern "C" fn(
    ip_address: *mut [u8; 16],
    port: u16,
    context: *const c_void
) -> bool;

pub type SendMessage = unsafe extern "C" fn(
    message_type: *mut c_char,
    message: *mut ByteArray,
    ip_address: *mut [u8; 16],
    port: u16,
    warn: bool,
    context: *const c_void
) -> bool;

pub type AddPendingMasternode = unsafe extern "C" fn(
    pro_tx_hash: *mut [u8; 32],
    session_id: *mut [u8; 32],
    context: *const c_void
) -> bool;

pub type StartManagerAsync = unsafe extern "C" fn(
    context: *const c_void
);

pub type UpdateSuccessBlock = unsafe extern "C" fn(
    context: *const c_void
);

pub type IsWaitingForNewBlock = unsafe extern "C" fn(
    context: *const c_void
) -> bool;

pub type SessionLifecycleListener = unsafe extern "C" fn(
    is_complete: bool,
    base_session_id: i32,
    client_session_id: *mut [u8; 32],
    denomination: u32,
    state: PoolState,
    message: PoolMessage,
    ip_address: *mut [u8; 16],
    joined: bool,
    context: *const c_void
);

pub type MixingLivecycleListener = unsafe extern "C" fn(
    is_complete: bool,
    is_interrupted: bool,
    pool_statuses: *const PoolStatus,
    pool_statuses_len: usize,
    context: *const c_void
);

pub type GetCoinJoinKeys = unsafe extern "C" fn(
    used: bool,
    context: *const c_void
) -> *mut CoinJoinKeys;

pub type DestroyCoinJoinKeys = unsafe extern "C" fn(
    coinjoin_keys: *mut CoinJoinKeys
);
