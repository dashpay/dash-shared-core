use std::collections::{HashSet, HashMap};
use std::net::SocketAddr;
use std::os::raw::c_void;
use std::sync::Arc;
use dashcore::hashes::{sha256, Hash};
use dashcore::blockdata::transaction::{OutPoint, Transaction, txin::TxIn, txout::TxOut};
use dashcore::consensus::Encodable;
use dashcore::secp256k1::rand;
use dashcore::secp256k1::rand::seq::SliceRandom;
use logging::*;
use dash_spv_crypto::crypto::byte_util::{Reversed, U32LE};
use dash_spv_crypto::network::TXIN_SEQUENCE;
use dash_spv_crypto::util::address::address;
use dash_spv_crypto::util::data_append::DataAppend;
use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::coin_selection::input_coin::InputCoin;
use crate::coinjoin::CoinJoin;
use crate::constants::MAX_COINJOIN_ROUNDS;
use crate::models::coin_control::{CoinControl, CoinType};
use crate::models::coinjoin_transaction_input::CoinJoinTransactionInput;
use crate::models::tx_destination::TxDestination;
use crate::models::CoinJoinClientOptions;
use crate::wallet_provider::WalletProvider;


#[derive(Clone)]
#[ferment_macro::opaque]
pub struct WalletEx {
    provider: Arc<WalletProvider>,
    options: Arc<CoinJoinClientOptions>,
    pub locked_coins_set: HashSet<OutPoint>,
    anonymizable_tally_cached_non_denom: bool,
    vec_anonymizable_tally_cached_non_denom: Vec<CompactTallyItem>,
    anonymizable_tally_cached: bool,
    vec_anonymizable_tally_cached: Vec<CompactTallyItem>,
    map_outpoint_rounds_cache: HashMap<OutPoint, i32>,
    unused_keys: HashMap<[u8; 32], Vec<u8>>,
    // TODO (DashJ): we may not need keyUsage, it is used as a way to audit unusedKeys
    key_usage: HashMap<[u8; 32], bool>,
    coinjoin_salt: [u8; 32],
    loaded_keys: bool,
}

#[ferment_macro::export]
impl WalletEx {
    pub fn new<
        GetWalletTx: Fn(*const c_void, [u8; 32]) -> Option<Transaction> + 'static,
        SignTransaction: Fn(*const c_void, Transaction, bool) -> Option<Transaction> + 'static,
        IsMineInput: Fn(*const c_void, OutPoint) -> bool + 'static,
        GetAvailableCoins: Fn(*const c_void, bool, CoinControl, &WalletEx) -> Vec<InputCoin> + 'static,
        SelectCoins: Fn(*const c_void, bool, bool, bool, i32, &WalletEx) -> Vec<CompactTallyItem> + 'static,
        InputsWithAmount: Fn(*const c_void, u64) -> u32 + 'static,
        FreshCJAddr: Fn(*const c_void, bool) -> String + 'static,
        CommitTx: Fn(*const c_void, Vec<TxOut>, CoinControl, bool, [u8; 32]) -> bool + 'static,
        IsSynced: Fn(*const c_void) -> bool + 'static,
        IsMasternodeOrDisconnectRequested: Fn(*const c_void, SocketAddr) -> bool + 'static,
        DisconnectMasternode: Fn(*const c_void, SocketAddr) -> bool + 'static,
        SendMessage: Fn(*const c_void, String, Vec<u8>, SocketAddr, bool) -> bool + 'static,
        AddPendingMasternode: Fn(*const c_void, [u8; 32], [u8; 32]) -> bool + 'static,
        StartManagerAsync: Fn(*const c_void) + 'static,
        GetCoinJoinKeys: Fn(*const c_void, bool) -> Vec<String> + 'static,
    >(
        context: *const c_void,
        options: CoinJoinClientOptions,
        get_wallet_transaction: GetWalletTx,
        sign_transaction: SignTransaction,
        is_mine_input: IsMineInput,
        available_coins: GetAvailableCoins,
        select_coins: SelectCoins,
        inputs_with_amount: InputsWithAmount,
        fresh_coinjoin_address: FreshCJAddr,
        commit_transaction: CommitTx,
        is_synced: IsSynced,
        is_masternode_or_disconnect_requested: IsMasternodeOrDisconnectRequested,
        disconnect_masternode: DisconnectMasternode,
        send_message: SendMessage,
        add_pending_masternode: AddPendingMasternode,
        start_manager_async: StartManagerAsync,
        get_coinjoin_keys: GetCoinJoinKeys,
    ) -> Self {
        let provider = Arc::new(WalletProvider::new(
            get_wallet_transaction,
            sign_transaction,
            is_mine_input,
            available_coins,
            select_coins,
            inputs_with_amount,
            fresh_coinjoin_address,
            commit_transaction,
            is_masternode_or_disconnect_requested,
            disconnect_masternode,
            is_synced,
            send_message,
            add_pending_masternode,
            start_manager_async,
            get_coinjoin_keys,
            context,
        ));
        WalletEx {
            provider,
            options: Arc::new(options),
            locked_coins_set: HashSet::new(),
            anonymizable_tally_cached_non_denom: false,
            vec_anonymizable_tally_cached_non_denom: Vec::new(),
            anonymizable_tally_cached: false,
            vec_anonymizable_tally_cached: Vec::new(),
            map_outpoint_rounds_cache: HashMap::new(),
            coinjoin_salt: [0; 32], // TODO: InitCoinJoinSalt ?
            loaded_keys: false,
            unused_keys: HashMap::with_capacity(1024),
            key_usage: HashMap::new(),
        }
    }

    pub fn lock_coin(&mut self, outpoint: OutPoint) {
        self.locked_coins_set.insert(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn unlock_coin(&mut self, outpoint: &OutPoint) {
        self.locked_coins_set.remove(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn is_locked_coin(&self, outpoint: &OutPoint) -> bool {
        self.locked_coins_set.contains(outpoint)
    }

    pub fn check_if_is_fully_mixed(&mut self, outpoint: OutPoint) -> bool {
        let rounds = self.get_real_outpoint_coinjoin_rounds(outpoint.clone(), 0);

        // Mix again if we don't have N rounds yet
        if rounds < self.options.coinjoin_rounds {
            return false;
        }

        // Try to mix a "random" number of rounds more than minimum.
        // If we have already mixed N + MaxOffset rounds, don't mix again.
        // Otherwise, we should mix again 50% of the time, this results in an exponential decay
        // N rounds 50% N+1 25% N+2 12.5%... until we reach N + GetRandomRounds() rounds where we stop.
        if rounds < self.options.coinjoin_rounds + self.options.coinjoin_random_rounds {
            let mut buffer = Vec::new();
            outpoint.consensus_encode(&mut buffer).unwrap();
            buffer.extend_from_slice(&self.coinjoin_salt.reversed());
            let hash = sha256::Hash::hash(&buffer).to_byte_array();
            if hash.u32_le() % 2 == 0 {
                return false;
            }
        }

        true
    }

    pub fn get_real_outpoint_coinjoin_rounds(&mut self, outpoint: OutPoint, rounds: i32) -> i32 {
        let rounds_max = MAX_COINJOIN_ROUNDS + self.options.coinjoin_random_rounds;

        if rounds >= rounds_max {
            // there can only be rounds_max rounds max
            return rounds_max - 1;
        }

        let mut rounds_ref = *self.map_outpoint_rounds_cache.entry(outpoint.clone()).or_insert(-10);

        if rounds_ref != -10 {
            return rounds_ref;
        }

        let wtx: Option<Transaction> = self.provider.get_wallet_transaction(outpoint.txid.to_byte_array());

        if wtx.is_none() {
            // no such tx in this wallet
            rounds_ref = -1;
            log_debug!(target: "CoinJoin", "FAILED    {:?} {} (no such tx)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        let transaction = wtx.unwrap();
        // bounds check
        if outpoint.vout >= transaction.output.len() as u32 {
            // should never actually hit this
            rounds_ref = -4;
            log_debug!(target: "CoinJoin", "FAILED    {:?} {} (bad index)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        let tx_out = &transaction.output[outpoint.vout as usize];

        if CoinJoin::is_collateral_amount(tx_out.value) {
            rounds_ref = -3;
            log_debug!(target: "CoinJoin", "UPDATED    {:?} {} (collateral)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        // make sure the final output is non-denominate
        if !CoinJoin::is_denominated_amount(tx_out.value) {
            rounds_ref = -2;
            log_debug!(target: "CoinJoin", "UPDATED    {:?} {} (non-denominated)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        for out in &transaction.output {
            if !CoinJoin::is_denominated_amount(out.value) {
                // this one is denominated but there is another non-denominated output found in the same tx
                rounds_ref = 0;
                log_debug!(target: "CoinJoin", "UPDATED    {:?} {} (non-denominated)", outpoint, rounds_ref);
                self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
                return rounds_ref;
            }
        }

        let mut n_shortest = -10; // an initial value, should be no way to get this by calculations
        let mut denom_found = false;

        // only denoms here so let's look up
        for txin_next in &transaction.input {
            let outpoint = txin_next.previous_output;
            if self.provider.is_mine_input(outpoint) {
                // let outpoint = TxOutPoint::new(txin_next.input_hash, txin_next.index);
                let n = self.get_real_outpoint_coinjoin_rounds(outpoint, rounds + 1);

                // denom found, find the shortest chain or initially assign nShortest with the first found value
                if n >= 0 && (n < n_shortest || n_shortest == -10) {
                    n_shortest = n;
                    denom_found = true;
                }
            }
        }

        rounds_ref = if denom_found {
            if n_shortest >= rounds_max - 1 { rounds_max } else { n_shortest + 1 }
        } else {
            0
        };

        log_debug!(target: "CoinJoin", "UPDATED    {:?} {} (coinjoin)", outpoint, rounds_ref);
        self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
        rounds_ref
    }

    pub fn has_collateral_inputs(&self, only_confirmed: bool) -> bool {
        let mut coin_control = CoinControl::new();
        coin_control.coin_type = CoinType::OnlyCoinJoinCollateral;
        let result = self.available_coins(only_confirmed, coin_control);
        !result.is_empty()
    }
    pub fn select_coins_grouped_by_addresses(
        &mut self,
        skip_denominated: bool,
        anonymizable: bool,
        skip_unconfirmed: bool,
        max_outpoints_per_address: i32
    ) -> Vec<CompactTallyItem> {
        // Try using the cache for already confirmed mixable inputs.
        // This should only be used if maxOupointsPerAddress was NOT specified.
        if max_outpoints_per_address == -1 && anonymizable && skip_unconfirmed {
            if skip_denominated && self.anonymizable_tally_cached_non_denom {
                log_debug!(target: "CoinJoin", "SelectCoinsGroupedByAddresses - using cache for non-denom inputs {}", self.vec_anonymizable_tally_cached_non_denom.len());
                return self.vec_anonymizable_tally_cached_non_denom.clone();
            }

            if !skip_denominated && self.anonymizable_tally_cached {
                log_debug!(target: "CoinJoin", "SelectCoinsGroupedByAddresses - using cache for all inputs {}", self.vec_anonymizable_tally_cached.len());
                return self.vec_anonymizable_tally_cached.clone();
            }
        }

        let vec_tally_ret = self.provider.select_coins(skip_denominated, anonymizable, skip_unconfirmed, max_outpoints_per_address, self);

        // Cache already confirmed mixable entries for later use.
        // This should only be used if nMaxOupointsPerAddress was NOT specified.
        if max_outpoints_per_address == -1 && anonymizable && skip_unconfirmed && !vec_tally_ret.is_empty() {
            if skip_denominated {
                log_debug!(target: "CoinJoin", "SelectCoinsGroupedByAddresses - set cache for non-denom inputs, len: {}", vec_tally_ret.len());
                self.vec_anonymizable_tally_cached_non_denom = vec_tally_ret.clone();
                self.anonymizable_tally_cached_non_denom = true;
            } else {
                log_debug!(target: "CoinJoin", "SelectCoinsGroupedByAddresses - set cache for all inputs, len: {}", vec_tally_ret.len());
                self.vec_anonymizable_tally_cached = vec_tally_ret.clone();
                self.anonymizable_tally_cached = true;
            }
        }

        vec_tally_ret
    }

    pub fn get_anonymizable_balance(&mut self, skip_denominated: bool, skip_unconfirmed: bool) -> u64 {
        if !self.options.enable_coinjoin {
            return 0;
        }

        let tally_items = self.select_coins_grouped_by_addresses(skip_denominated, true, skip_unconfirmed, -1);

        if tally_items.is_empty() {
            return 0;
        }

        let mut total = 0;
        let smallest_denom = CoinJoin::get_smallest_denomination();
        let mixing_collateral = CoinJoin::get_collateral_amount();

        for item in tally_items {
            let is_denominated = CoinJoin::is_denominated_amount(item.amount);

            if skip_denominated && is_denominated {
                continue;
            }

            // assume that the fee to create denoms should be mixing collateral at max
            if item.amount >= smallest_denom + if is_denominated { 0 } else { mixing_collateral } {
                total += item.amount;
            }
        }

        total
    }
    pub fn get_unused_key(&mut self, internal: bool) -> TxDestination {
        if self.unused_keys.is_empty() {
            if !self.key_usage.is_empty() && self.key_usage.values().all(|used| !used) {
                log_info!(target: "CoinJoin", "WalletEx - keyUsage map has unused keys, unused key count: {}", self.unused_keys.len());
            }
            return Some(self.fresh_receive_key(internal));
        }

        if let Some((&key, item)) = self.unused_keys.iter().next() {
            let unused = item.clone();
            // let key = *pair.0;
            // let item = pair.1.clone();
            log_info!(target: "CoinJoin", "WalletEx - reusing key - is this key used: {}, unused key count: {}", self.key_usage.get(&key).unwrap(), self.unused_keys.len());
            // remove the key
            self.unused_keys.remove(&key);
            self.key_usage.insert(key, true);
            Some(unused)
        } else {
            None
        }

    }

    pub fn add_unused_key(&mut self, destination: Vec<u8>) {
        let key_id = sha256::Hash::hash(&destination).to_byte_array();
        log_debug!(target: "CoinJoin", "WalletEx - add unused key: {:?}", address::with_script_sig(&destination, &self.options.chain_type.script_map()));
        self.unused_keys.insert(key_id, destination);
        self.key_usage.insert(key_id, false);
    }
    pub fn refresh_unused_keys(&mut self) {
        self.unused_keys.clear();
        let issued_keys = self.provider.get_issued_receive_keys();

        for key in &issued_keys {
            let pub_key = Vec::<u8>::script_pub_key_for_address(key, &self.options.chain_type.script_map());
            let key_id = sha256::Hash::hash(&pub_key).to_byte_array();
            self.unused_keys.insert(key_id, pub_key);
            self.key_usage.insert(key_id, false);
        }

        let used_keys = self.provider.get_used_receive_keys();

        for used_key in &used_keys {
            let pub_key = Vec::<u8>::script_pub_key_for_address(used_key, &self.options.chain_type.script_map());
            let key_id = sha256::Hash::hash(&pub_key).to_byte_array();
            self.unused_keys.remove(&key_id);
            self.key_usage.insert(key_id, true);
        }

        for (_, key) in &self.unused_keys {
            log_debug!(target: "CoinJoin", "WalletEx - unused key: {:?}", address::with_script_sig(key, &self.options.chain_type.script_map()));
        }

        for (key_id, used) in &self.key_usage {
            if !used {
                if let Some(key) = self.unused_keys.get(key_id) {
                    log_debug!(target: "CoinJoin", "WalletEx - unused key: {:?}", address::with_script_sig(key, &self.options.chain_type.script_map()));
                }
            }
        }

        self.loaded_keys = true;

    }

    pub fn process_used_scripts(&mut self, scripts: &Vec<Vec<u8>>) {
        for script in scripts {
            let key_id = sha256::Hash::hash(script).to_byte_array();

            if self.loaded_keys {
                self.key_usage.insert(key_id, true);
                self.unused_keys.remove(&key_id);
            }

            if let Some(key) = self.unused_keys.get(&key_id) {
                log_debug!(target: "CoinJoin", "WalletEx - key used: {:?}", address::with_script_pub_key(key, &self.options.chain_type.script_map()));
            }
        }
    }
}
impl WalletEx {


    pub fn available_coins(&self, only_safe: bool, coin_control: CoinControl) -> Vec<InputCoin> {
        self.provider.available_coins(only_safe, coin_control, self)
    }

    pub fn get_wallet_transaction(&self, hash: [u8; 32]) -> Option<Transaction> {
        self.provider.get_wallet_transaction(hash)
    }

    /**
     * Count the number of unspent outputs that have a certain value
     */
    pub fn count_inputs_with_amount(&self, value: u64) -> u32 {
        self.provider.count_inputs_with_amount(value)
    }


    pub fn remove_unused_key(&mut self, destination: &TxDestination) {
        if let Some(key) = destination {
            let key_id = sha256::Hash::hash(key).to_byte_array();
            self.unused_keys.remove(&key_id);
            self.key_usage.insert(key_id, true);
            log_debug!(target: "CoinJoin", "WalletEx - remove unused key: {:?}", address::with_script_sig(&key, &self.options.chain_type.script_map()));
        }
    }

    fn fresh_receive_key(&mut self, internal: bool) -> Vec<u8> {
        let fresh_address = self.provider.get_fresh_coinjoin_address(internal);
        let script_map = self.options.chain_type.script_map();
        let fresh_key = Vec::<u8>::script_pub_key_for_address(&fresh_address, &script_map);
        log_debug!(target: "CoinJoin", "WalletEx - fresh key: {:?}", address::with_script_pub_key(&fresh_key, &script_map));
        let key_id = sha256::Hash::hash(&fresh_key).to_byte_array();
        self.key_usage.insert(key_id, true);
        fresh_key
    }


    pub fn commit_transaction(&self, vec_send: Vec<TxOut>, coin_control: CoinControl, is_denominating: bool, client_session_id: [u8; 32]) -> bool {
        self.provider.commit_transaction(vec_send, coin_control, is_denominating, client_session_id)
    }

    pub fn sign_transaction(&self, tx: Transaction, anyone_can_pay: bool) -> Option<Transaction> {
        self.provider.sign_transaction(tx, anyone_can_pay)
    }
    pub fn select_tx_dsins_by_denomination(&mut self, denom: u32, value_max: u64, vec_tx_dsin_ret: &mut Vec<CoinJoinTransactionInput>) -> bool {
        let mut value_total: u64 = 0;
        let mut set_recent_tx_ids = HashSet::new();
        vec_tx_dsin_ret.clear();
    
        if !CoinJoin::is_valid_denomination(denom) {
            return false;
        }
    
        let denom_amount = CoinJoin::denomination_to_amount(denom);
        let mut coin_control = CoinControl::new();
        coin_control.coin_type = CoinType::OnlyReadyToMix;
    
        let mut coins = self.available_coins(true, coin_control);
        coins.shuffle(&mut rand::thread_rng());
    
        for out in coins.iter() {
            let tx_hash = out.tx_outpoint.txid;
            let value = out.output.value;
    
            if set_recent_tx_ids.contains(&tx_hash) || value_total + value > value_max || value as i64 != denom_amount {
                continue;
            }

            let txin = TxIn {
                previous_output: out.tx_outpoint,
                script_sig: Default::default(),
                sequence: TXIN_SEQUENCE,
                witness: Default::default(),
            };

    
            // let txin = TransactionInput {
            //     input_hash: tx_hash,
            //     index: out.tx_outpoint.index,
            //     script: None,
            //     signature: Some(Vec::new()),
            //     sequence: TXIN_SEQUENCE
            // };
            let rounds = self.get_real_outpoint_coinjoin_rounds(out.tx_outpoint.clone(), 0);
    
            value_total += value;
            vec_tx_dsin_ret.push(CoinJoinTransactionInput::new(txin, rounds));
            set_recent_tx_ids.insert(tx_hash);
        }
    
        value_total > 0
    }

    pub fn select_denominated_amounts(&self, value_max: u64, set_amounts_ret: &mut HashSet<u64>) -> bool {
        let mut value_total: u64 = 0;
        set_amounts_ret.clear();

        let mut coin_control = CoinControl::new();
        coin_control.coin_type = CoinType::OnlyReadyToMix;
        let mut coins = self.available_coins(true, coin_control);

        // larger denoms first
        coins.sort_by(|a, b| b.output.value.cmp(&a.output.value));

        for out in coins.iter() {
            let value = out.output.value;
            if value_total + value <= value_max {
                value_total += value;
                set_amounts_ret.insert(value);
            }
        }

        value_total >= CoinJoin::get_smallest_denomination()
    }

    pub fn is_masternode_or_disconnect_requested(&self, address: SocketAddr) -> bool {
        self.provider.is_masternode_or_disconnect_requested(address)
    }

    pub fn disconnect_masternode(&self, address: SocketAddr) -> bool {
        self.provider.disconnect_masternode(address)
    }
    pub fn is_synced(&self) -> bool {
        self.provider.is_synced()
    }
    pub fn send_message(&self, message: Vec<u8>, msg_type: String, address: SocketAddr, warn: bool) -> bool {
        self.provider.send_message(message, msg_type, address, warn)
    }

    pub fn add_pending_masternode(&self, pro_tx_hash: [u8; 32], session_id: [u8; 32]) -> bool {
        self.provider.add_pending_masternode(pro_tx_hash, session_id)
    }

    pub fn start_manager_async(&self) {
        self.provider.start_manager_async()
    }

    fn clear_anonymizable_caches(&mut self) {
        self.anonymizable_tally_cached_non_denom = false;
        self.anonymizable_tally_cached = false;
    }

    // fn is_mine_input(&self, txin: &OutPoint) -> bool {
    //     (self.is_mine_input)(self.context, txin)
    // }


}
