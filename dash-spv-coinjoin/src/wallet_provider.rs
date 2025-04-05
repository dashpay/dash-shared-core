use std::net::SocketAddr;
use std::os::raw::c_void;
use std::sync::Arc;
use dashcore::blockdata::transaction::{OutPoint, Transaction, txout::TxOut};
use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::coin_selection::input_coin::InputCoin;
use crate::models::coin_control::CoinControl;
use crate::wallet_ex::WalletEx;

#[ferment_macro::opaque]
pub struct WalletProvider {
    context: *const c_void,
    get_wallet_transaction: Arc<dyn Fn(*const c_void, [u8; 32]) -> Option<Transaction>>,
    sign_transaction: Arc<dyn Fn(*const c_void, Transaction, bool) -> Option<Transaction>>,
    is_mine_input: Arc<dyn Fn(*const c_void, OutPoint) -> bool>,
    available_coins: Arc<dyn Fn(*const c_void, bool, CoinControl, &WalletEx) -> Vec<InputCoin>>,
    select_coins: Arc<dyn Fn(*const c_void, bool, bool, bool, i32, &WalletEx) -> Vec<CompactTallyItem>>,
    inputs_with_amount: Arc<dyn Fn(*const c_void, u64) -> u32>,
    fresh_coinjoin_address: Arc<dyn Fn(*const c_void , bool) -> String>,
    commit_transaction: Arc<dyn Fn(*const c_void, Vec<TxOut>, CoinControl, bool, [u8; 32]) -> bool>,
    is_masternode_or_disconnect_requested: Arc<dyn Fn(*const c_void, SocketAddr) -> bool>,
    disconnect_masternode: Arc<dyn Fn(*const c_void, SocketAddr) -> bool>,
    is_synced: Arc<dyn Fn(*const c_void) -> bool>,
    send_message: Arc<dyn Fn(*const c_void, String, Vec<u8>, SocketAddr, bool) -> bool>,
    add_pending_masternode: Arc<dyn Fn(*const c_void, [u8; 32], [u8; 32]) -> bool>,
    start_manager_async: Arc<dyn Fn(*const c_void)>,
    get_coinjoin_keys: Arc<dyn Fn(*const c_void, bool) -> Vec<String>>,
}

#[ferment_macro::export]
impl WalletProvider {

    pub fn new<
        GWT: Fn(*const c_void, [u8; 32]) -> Option<Transaction> + 'static,
        ST: Fn(*const c_void, Transaction, bool) -> Option<Transaction> + 'static,
        IMI: Fn(*const c_void, OutPoint) -> bool + 'static,
        AC: Fn(*const c_void, bool, CoinControl, &WalletEx) -> Vec<InputCoin> + 'static,
        SC: Fn(*const c_void, bool, bool, bool, i32, &WalletEx) -> Vec<CompactTallyItem> + 'static,
        IWA: Fn(*const c_void, u64) -> u32 + 'static,
        FCA: Fn(*const c_void, bool) -> String + 'static,
        CT: Fn(*const c_void, Vec<TxOut>, CoinControl, bool, [u8; 32]) -> bool + 'static,
        IMODR: Fn(*const c_void, SocketAddr) -> bool + 'static,
        DM: Fn(*const c_void, SocketAddr) -> bool + 'static,
        IS: Fn(*const c_void) -> bool + 'static,
        SM: Fn(*const c_void, String, Vec<u8>, SocketAddr, bool) -> bool + 'static,
        APM: Fn(*const c_void, [u8; 32], [u8; 32]) -> bool + 'static,
        SMA: Fn(*const c_void) + 'static,
        GCK: Fn(*const c_void, bool) -> Vec<String> + 'static,
    >(
        get_wallet_transaction: GWT,
        sign_transaction: ST,
        is_mine_input: IMI,
        available_coins: AC,
        select_coins: SC,
        inputs_with_amount: IWA,
        fresh_coinjoin_address: FCA,
        commit_transaction: CT,
        is_masternode_or_disconnect_requested: IMODR,
        disconnect_masternode: DM,
        is_synced: IS,
        send_message: SM,
        add_pending_masternode: APM,
        start_manager_async: SMA,
        get_coinjoin_keys: GCK,
        context: *const c_void,
    ) -> WalletProvider {
        Self {
            context,
            get_wallet_transaction: Arc::new(get_wallet_transaction),
            sign_transaction: Arc::new(sign_transaction),
            is_mine_input: Arc::new(is_mine_input),
            available_coins: Arc::new(available_coins),
            select_coins: Arc::new(select_coins),
            inputs_with_amount: Arc::new(inputs_with_amount),
            fresh_coinjoin_address: Arc::new(fresh_coinjoin_address),
            commit_transaction: Arc::new(commit_transaction),
            is_masternode_or_disconnect_requested: Arc::new(is_masternode_or_disconnect_requested),
            disconnect_masternode: Arc::new(disconnect_masternode),
            is_synced: Arc::new(is_synced),
            send_message: Arc::new(send_message),
            add_pending_masternode: Arc::new(add_pending_masternode),
            start_manager_async: Arc::new(start_manager_async),
            get_coinjoin_keys: Arc::new(get_coinjoin_keys),
        }
    }
}

impl WalletProvider {
    /**
    * Count the number of unspent outputs that have a certain value
    */
    pub(crate) fn count_inputs_with_amount(&self, value: u64) -> u32 {
        (self.inputs_with_amount)(self.context, value)
    }
    pub(crate) fn get_wallet_transaction(&self, hash: [u8; 32]) -> Option<Transaction> {
        (self.get_wallet_transaction)(self.context, hash)
    }
    pub(crate) fn commit_transaction(&self, vec_send: Vec<TxOut>, coin_control: CoinControl, is_denominating: bool, client_session_id: [u8; 32]) -> bool {
        (self.commit_transaction)(self.context, vec_send, coin_control, is_denominating, client_session_id)
    }
    pub(crate) fn sign_transaction(&self, tx: Transaction, anyone_can_pay: bool) -> Option<Transaction> {
        (self.sign_transaction)(self.context, tx, anyone_can_pay)
    }
    pub(crate) fn is_masternode_or_disconnect_requested(&self, address: SocketAddr) -> bool {
        (self.is_masternode_or_disconnect_requested)(self.context, address)
    }
    pub(crate) fn disconnect_masternode(&self, address: SocketAddr) -> bool {
        (self.disconnect_masternode)(self.context, address)
    }
    pub(crate) fn is_synced(&self) -> bool {
        (self.is_synced)(self.context)
    }
    pub(crate) fn send_message(&self, message: Vec<u8>, msg_type: String, address: SocketAddr, warn: bool) -> bool {
        (self.send_message)(self.context, msg_type, message, address, warn)
    }
    pub(crate) fn add_pending_masternode(&self, pro_tx_hash: [u8; 32], session_id: [u8; 32]) -> bool {
        (self.add_pending_masternode)(self.context, pro_tx_hash, session_id)
    }
    pub(crate) fn start_manager_async(&self) {
        (self.start_manager_async)(self.context)
    }
    pub(crate) fn get_issued_receive_keys(&self) -> Vec<String> {
        (self.get_coinjoin_keys)(self.context, false)
    }

    pub(crate) fn get_used_receive_keys(&self) -> Vec<String> {
        (self.get_coinjoin_keys)(self.context, true)
    }
    pub(crate) fn get_fresh_coinjoin_address(&self, internal: bool) -> String {
        (self.fresh_coinjoin_address)(self.context, internal)
    }
    pub(crate) fn select_coins(&self, skip_denominated: bool, anonymizable: bool, skip_unconfirmed: bool, max_outpoints_per_address: i32, wallet_ex: &WalletEx) -> Vec<CompactTallyItem> {
        (self.select_coins)(self.context, skip_denominated, anonymizable, skip_unconfirmed, max_outpoints_per_address, wallet_ex)
    }

    pub(crate) fn available_coins(&self, only_safe: bool, coin_control: CoinControl, wallet_ex: &WalletEx) -> Vec<InputCoin> {
        (self.available_coins)(self.context, only_safe, coin_control, wallet_ex)
    }

    pub(crate) fn is_mine_input(&self, outpoint: OutPoint) -> bool {
        (self.is_mine_input)(self.context, outpoint)
    }

}