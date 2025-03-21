use std::{cell::RefCell, collections::VecDeque, rc::Rc, time::{SystemTime, UNIX_EPOCH}};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::raw::c_void;
use std::sync::{Arc, RwLock};
use dashcore::blockdata::transaction::{OutPoint, Transaction};
use dashcore::hashes::Hash;
use dashcore::hash_types::{ProTxHash, Txid};
use dashcore::prelude::DisplayHex;
use dashcore::secp256k1::rand::{thread_rng, Rng};
use dashcore::secp256k1::rand::prelude::SliceRandom;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use logging::*;
use crate::{coinjoin::CoinJoin, coinjoin_client_session::CoinJoinClientSession, constants::{COINJOIN_AUTO_TIMEOUT_MAX, COINJOIN_AUTO_TIMEOUT_MIN}, messages::{coinjoin_message::CoinJoinMessage, CoinJoinQueueMessage, PoolState, PoolStatus}, models::{Balance, CoinJoinClientOptions}, wallet_ex::WalletEx};
use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::constants::COINJOIN_QUEUE_TIMEOUT;
use crate::masternode_meta_data_manager::MasternodeMetadataManager;
use crate::messages::PoolMessage;
use crate::provider::CoinJoinProvider;

// #[ferment_macro::opaque]
pub struct CoinJoinClientManager {
    pub wallet_ex: Rc<RefCell<WalletEx>>,
    coinjoin: Arc<RwLock<CoinJoin>>,
    options: Rc<RefCell<CoinJoinClientOptions>>,
    masternodes_used: Vec<ProTxHash>,
    last_masternode_used: usize,
    last_time_report_too_recent: u64,
    tick: i32,
    do_auto_next_run: i32,
    pub is_mixing: bool,
    is_shutting_down: bool,
    deq_sessions: VecDeque<CoinJoinClientSession>,
    continue_mixing_on_status: Vec<PoolStatus>,
    str_auto_denom_result: String,
    stop_on_nothing_to_do: bool,
    mixing_finished: bool,
    coinjoin_queue: Vec<CoinJoinQueueMessage>,
    spamming_masternodes: HashMap<ProTxHash, u64>,
    pub masternode_metadata_manager: MasternodeMetadataManager,

    provider: Arc<CoinJoinProvider>,
}

#[ferment_macro::export]
impl CoinJoinClientManager {
    pub fn new<
        GML: Fn(*const c_void) -> MasternodeList + 'static,
        USB: Fn(*const c_void) + 'static,
        IWFNB: Fn(*const c_void) -> bool + 'static,
        SLL: Fn(*const c_void, bool, i32, [u8; 32], u32, PoolState, PoolMessage, PoolStatus, Option<SocketAddr>, bool) + 'static,
        MLL: Fn(*const c_void, bool, bool, Vec<PoolStatus>) + 'static,
        MBH: Fn(*const c_void, [u8; 32]) -> Option<QualifiedMasternodeListEntry> + 'static,
        VMC: Fn(*const c_void) -> usize + 'static,
    >(
        wallet_ex: WalletEx,
        coinjoin: CoinJoin,
        options: CoinJoinClientOptions,
        get_masternode_list: GML,
        update_success_block: USB,
        is_waiting_for_new_block: IWFNB,
        session_lifecycle_listener: SLL,
        mixing_lifecycle_listener: MLL,
        masternode_by_hash: MBH,
        valid_mns_count: VMC,

        context: *const c_void
    ) -> CoinJoinClientManager {
        let provider = Arc::new(CoinJoinProvider::new(
            get_masternode_list,
            update_success_block,
            is_waiting_for_new_block,
            session_lifecycle_listener,
            mixing_lifecycle_listener,
            masternode_by_hash,
            valid_mns_count,
            context));


        Self {
            wallet_ex: Rc::new(RefCell::new(wallet_ex)),
            coinjoin: Arc::new(RwLock::new(coinjoin)),
            options: Rc::new(RefCell::new(options)),
            masternodes_used: vec![],
            last_masternode_used: 0,
            last_time_report_too_recent: 0,
            tick: 0,
            do_auto_next_run: COINJOIN_AUTO_TIMEOUT_MIN,
            is_mixing: false,
            is_shutting_down: false,
            deq_sessions: VecDeque::new(),
            continue_mixing_on_status: vec![],
            str_auto_denom_result: String::new(),
            stop_on_nothing_to_do: false,
            mixing_finished: false,
            coinjoin_queue: Vec::new(),
            spamming_masternodes: HashMap::new(),
            masternode_metadata_manager: MasternodeMetadataManager::new(),
            provider,
        }
    }

    pub fn process_raw_message(&mut self, from: SocketAddr, message: &[u8], message_type: &str) {
        let coinjoin_message = CoinJoinMessage::from_message(message, message_type);
        self.process_message(from, coinjoin_message);
    }

    pub fn process_message(&mut self, from: SocketAddr, message: CoinJoinMessage) {
        if !self.options.borrow().enable_coinjoin {
            return;
        }

        if !self.wallet_ex.borrow().is_synced() {
            return;
        }

        if let CoinJoinMessage::BroadcastTx(broadcast_tx) = message {
            let mut lock = self.coinjoin.write().unwrap();
            lock.add_dstx(broadcast_tx.clone());
            drop(lock);
        } else {
            let mut update_success_block = false;

            for session in &mut self.deq_sessions {
                update_success_block = session.process_message(&from, &message);
            }

            if update_success_block {
                self.updated_success_block();
            }
        }
    }

    pub fn start_mixing(&mut self) -> bool {
        self.queue_mixing_lifecycle_listeners(false, false);

        if !self.is_mixing {
            self.is_mixing = true;
            self.is_shutting_down = false;
            true
        } else {
            false
        }
    }

    pub fn set_stop_on_nothing_to_do(&mut self, stop: bool) {
        self.stop_on_nothing_to_do = stop;
    }

    pub fn stop_mixing(&mut self) {
        self.is_mixing = false;
        self.is_shutting_down = false;
        self.queue_mixing_lifecycle_listeners(self.mixing_finished, true);
    }

    pub fn do_maintenance(&mut self, balance_info: Balance) {
        if !self.options.borrow().enable_coinjoin {
            return;
        }

        if !self.wallet_ex.borrow().is_synced() {
            log_debug!(target: "CoinJoin", "not synced");
            return;
        }

        self.check_queue();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.spamming_masternodes.retain(|_, v| (*v + COINJOIN_QUEUE_TIMEOUT) > current_time);

        self.tick += 1;
        self.check_timeout();
        self.process_pending_dsa_request();

        if self.do_auto_next_run >= self.tick && !self.is_shutting_down {
            self.do_automatic_denominating(balance_info, false);
            let mut rng = thread_rng();
            self.do_auto_next_run = self.tick + COINJOIN_AUTO_TIMEOUT_MIN + rng.gen_range(0..COINJOIN_AUTO_TIMEOUT_MAX - COINJOIN_AUTO_TIMEOUT_MIN);
        }

        // are all sessions idle?
        let mut is_idle = !self.deq_sessions.is_empty(); // false if no sessions created yet

        for session in &self.deq_sessions {
            if !session.has_nothing_to_do {
                is_idle = false;
                break;
            }
        }

        // if all sessions idle, then trigger stop mixing
        if is_idle {
            let statuses = self.get_sessions_status();

            for status in statuses {
                if status == PoolStatus::Finished || (status.is_error() && !self.continue_mixing_on_status.contains(&status)) {
                    self.trigger_mixing_finished();
                }
            }
        }
    }

    pub fn initiate_shutdown(&mut self) {
        if self.is_shutting_down {
            return;
        }

        self.is_shutting_down = true;
        self.coinjoin_queue.clear();
    }

    pub fn do_automatic_denominating(&mut self, balance_info: Balance, dry_run: bool) -> bool {
        if !self.options.borrow().enable_coinjoin || (!dry_run && !self.is_mixing) {
            return false;
        }

        if !dry_run && !self.wallet_ex.borrow().is_synced() {
            log_info!(target: "CoinJoin", "wallet is not synced.");
            self.str_auto_denom_result = "Wallet is not synced.".to_string();
            return false;
        }

        // TODO: recheck
        // if (!dryRun && mixingWallet.isEncrypted() && context.coinJoinManager.requestKeyParameter(mixingWallet) == null) {
        //     strAutoDenomResult = "Wallet is locked.";
        //     return false;
        // }

        let mn_count_enabled = if dry_run { 0 } else { self.get_valid_mns_count(&self.get_mn_list()) };

        // If we've used 90% of the Masternode list then drop the oldest first ~30%
        let threshold_high = (mn_count_enabled as f64 * 0.9) as usize;
        let threshold_low = (threshold_high as f64 * 0.7) as usize;

        if !self.is_waiting_for_new_block() {
            if self.masternodes_used.len() != self.last_masternode_used {
                self.last_masternode_used = self.masternodes_used.len();
            }
        }

        if self.masternodes_used.len() > threshold_high {
            // remove the first masternodesUsed.size() - thresholdLow masternodes
            // this might be a problem for SPV
            self.masternodes_used.drain(0..(self.masternodes_used.len() - threshold_low));
            log_warn!(target: "CoinJoin", "masternodesUsed: new size: {}, threshold: {}", self.masternodes_used.len(), threshold_high);
        }

        let mut result = true;

        if self.deq_sessions.len() < self.options.borrow().coinjoin_sessions as usize {
            let new_session = CoinJoinClientSession::new(
                self.coinjoin.clone(),
                self.options.clone(),
                self.wallet_ex.clone(),
                // queue_manager.clone(),
                Arc::clone(&self.provider)
            );

            log_info!(target: "CoinJoin", "creating new session, current session amount: {}", self.deq_sessions.len());
            self.deq_sessions.push_back(new_session);
        }

        let mut sessions_to_process: Vec<_> = self.deq_sessions.drain(..).collect();

        for session in sessions_to_process.iter_mut() {
            // (DashJ) we may not need this
            if !dry_run && self.is_waiting_for_new_block() {
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

                if current_time - self.last_time_report_too_recent > 15 {
                    self.str_auto_denom_result = "Last successful action was too recent.".to_string();
                    log_info!(target: "CoinJoin", "do_automatic_denominating {}", self.str_auto_denom_result);
                    self.last_time_report_too_recent = current_time;
                }

                result = false;
                break;
            }

            result &= session.do_automatic_denominating(self, dry_run, balance_info.clone());
        }

        self.deq_sessions.extend(sessions_to_process);

        result
    }

    pub fn finish_automatic_denominating(&mut self, client_session_id: [u8; 32]) -> bool {
        let mut sessions: Vec<_> = self.deq_sessions.drain(..).collect();
        let mut finished = false;

        for session in &mut sessions {
            if session.id == client_session_id {
                finished = session.finish_automatic_denominating(self);
                break;
            }
        }

        self.deq_sessions.extend(sessions);

        finished
    }

    pub fn add_used_masternode(&mut self, pro_tx_hash: ProTxHash) {
        self.masternodes_used.push(pro_tx_hash);
    }

    pub fn get_random_not_used_masternode(&self) -> Option<QualifiedMasternodeListEntry> {
        let mn_list = self.get_mn_list();
        let count_enabled = self.get_valid_mns_count(&mn_list);
        let count_not_excluded = count_enabled - self.masternodes_used.len();

        if count_not_excluded < 1 {
            return None;
        }

        // fill a vector
        let mut vp_masternodes_shuffled: Vec<&QualifiedMasternodeListEntry> = Vec::with_capacity(count_enabled);
        mn_list.masternodes.values().filter(|mn| mn.masternode_list_entry.is_valid).for_each(|mn| {
            vp_masternodes_shuffled.push(mn);
        });

        // shuffle pointers
        let mut rng = thread_rng();
        vp_masternodes_shuffled.shuffle(&mut rng);

        // loop through
        for dmn in vp_masternodes_shuffled {
            if self.masternodes_used.contains(&dmn.masternode_list_entry.pro_reg_tx_hash) {
                continue;
            }

            log_info!(target: "CoinJoin", "mn found, proTxHash={}", dmn.masternode_list_entry.pro_reg_tx_hash.as_byte_array().to_lower_hex_string());
            return Some(dmn.clone());
        }

        log_error!(target: "CoinJoin", "failed get_random_not_used_masternode");
        None
    }
    pub fn process_pending_dsa_request(&mut self) {
        for session in self.deq_sessions.iter_mut() {
            if session.process_pending_dsa_request() {
                self.str_auto_denom_result = "Mixing in progress...".to_string();
            }
        }
    }

    pub fn get_sessions_status(&self) -> Vec<PoolStatus> {
        let mut sessions_status = Vec::new();

        for session in self.deq_sessions.iter() {
            sessions_status.push(session.base_session.status);
        }
        sessions_status
    }

    pub fn is_waiting_for_new_block(&self) -> bool {
        self.provider.is_waiting_for_new_block()
    }

    pub fn refresh_unused_keys(&mut self) {
        self.wallet_ex.borrow_mut().refresh_unused_keys();
    }
    pub fn check_if_is_fully_mixed(&mut self, outpoint: OutPoint) -> bool {
        self.wallet_ex.borrow_mut().check_if_is_fully_mixed(outpoint)
    }

    pub fn process_ds_queue(&mut self, from_peer: SocketAddr, message: &[u8]) {
        let mut dsq = CoinJoinQueueMessage::from_message(message);
        // process every dsq only once
        for q in self.coinjoin_queue.iter() {
            if q == &dsq {
                return;
            }

            if q.ready == dsq.ready && q.pro_tx_hash == dsq.pro_tx_hash {
                // no way the same mn can send another dsq with the same readiness this soon
                if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    self.spamming_masternodes.insert(dsq.pro_tx_hash, current_time);
                    log_debug!(target: "CoinJoin", "Peer {:?} is sending WAY too many dsq messages for a masternode {:?}", from_peer.ip(), dsq.pro_tx_hash);
                }
                return;
            }
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if dsq.is_time_out_of_bounds(current_time) {
            return;
        }

        if let Some(dmn) = self.provider.get_masternode_by_hash(dsq.pro_tx_hash.to_byte_array()) {
            if !dsq.check_signature(dmn.masternode_list_entry.operator_public_key.0, false) {
                // add 10 points to ban score
                return;
            }

            // if the queue is ready, submit if we can
            if dsq.ready && self.try_submit_denominate(dmn.masternode_list_entry.service_address.clone()) {
                log_info!(target: "CoinJoin", "CoinJoin queue ({}) is ready on masternode {}", dsq, dmn.masternode_list_entry.service_address);
            } else {
                if let Some(meta_info) = self.masternode_metadata_manager.get_meta_info(dmn.masternode_list_entry.pro_reg_tx_hash, true) {
                    let last_dsq = meta_info.last_dsq;
                    let dsq_threshold = self.masternode_metadata_manager.get_dsq_threshold(dmn.masternode_list_entry.pro_reg_tx_hash, self.provider.get_valid_mns_count());

                    // don't allow a few nodes to dominate the queuing process
                    if last_dsq != 0 && dsq_threshold > self.masternode_metadata_manager.dsq_count {
                        if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                            self.spamming_masternodes.insert(dsq.pro_tx_hash, current_time);
                            log_info!(target: "CoinJoin", "Masternode {} is sending too many dsq messages", dmn.masternode_list_entry.pro_reg_tx_hash.to_string());
                        }
                        return;
                    }
                } else {
                    return;
                }

                self.masternode_metadata_manager.allow_mixing(dmn.masternode_list_entry.pro_reg_tx_hash);
                let log_msg = format!("new CoinJoin queue ({}) from masternode {}", dsq, dmn.masternode_list_entry.service_address.to_string());

                if dsq.ready {
                    log_info!(target: "CoinJoin", "{}", log_msg);
                } else {
                    log_debug!(target: "CoinJoin", "{}", log_msg);
                }
                // TODO: actually it doesn't make sense since 'tried' is never used after
                dsq.tried = self.mark_already_joined_queue_as_tried(&dsq.pro_tx_hash);
                self.coinjoin_queue.push(dsq);
            }
        }
    }
    pub fn update_block_tip(&mut self, block_height: u32) {
        let mut lock = self.coinjoin.write().unwrap();
        lock.update_block_tip(block_height);
        drop(lock);
    }
    pub fn is_mixing_fee_tx(&self, tx_id: &Txid) -> bool {
        for session in &self.deq_sessions {
            if session.is_mixing_fee_tx(tx_id) {
                return true;
            }
        }
        false
    }
    pub fn change_options(&mut self, new_options: CoinJoinClientOptions) {
        if new_options != *self.options.borrow() {
            if self.options.borrow().enable_coinjoin || new_options.enable_coinjoin {
                log_info!(target: "CoinJoin", "updating client options: {:?}", new_options);
            }
            *self.options.borrow_mut() = new_options.clone();
        }
    }
    pub fn process_used_scripts(&mut self, scripts: &Vec<Vec<u8>>) {
        self.wallet_ex.borrow_mut().process_used_scripts(scripts);
    }


    pub fn get_real_outpoint_coinjoin_rounds(&mut self, outpoint: OutPoint, rounds: i32) -> i32 {
        self.wallet_ex.borrow_mut().get_real_outpoint_coinjoin_rounds(outpoint, rounds)
    }

    pub fn reset_pool(&mut self) {
        self.masternodes_used.clear();

        for session in &mut self.deq_sessions {
            session.reset_pool();
        }
        self.deq_sessions.clear();
        self.tick = 0;
        self.do_auto_next_run = COINJOIN_AUTO_TIMEOUT_MIN;
    }
    pub fn stop_and_reset(&mut self) {
        if self.is_mixing {
            self.reset_pool();
            self.stop_mixing();
        }
    }

    pub fn has_collateral_inputs(&self, only_confirmed: bool) -> bool {
        self.wallet_ex.borrow().has_collateral_inputs(only_confirmed)
    }

    pub fn is_locked_coin(&self, outpoint: &OutPoint) -> bool {
        self.wallet_ex.borrow().locked_coins_set.contains(outpoint)
    }

    pub fn lock_outputs(&mut self, tx_hash: Txid, indices: Vec<u32>) {
        for index in indices {
            self.wallet_ex.borrow_mut().lock_coin(OutPoint::new(tx_hash, index));
        }
    }

    pub fn unlock_outputs(&mut self, tx: &Transaction) {
        for input in tx.input.iter() {
            self.wallet_ex.borrow_mut().unlock_coin(&input.previous_output);
        }
    }

    pub fn session_amount(&self) -> usize {
        let len = self.deq_sessions.len();

        println!("[RUST] CoinJoin: sessions {:?}", len);
        for session in self.deq_sessions.iter() {
            println!("[RUST] CoinJoin: session status: {:?}", session.base_session.status);
        }

        len
    }

    pub fn select_coins_grouped_by_addresses(
        &mut self,
        skip_denominated: bool,
        anonymizable: bool,
        skip_unconfirmed: bool,
        max_outpoints_per_address: i32) -> Vec<CompactTallyItem> {
        self.wallet_ex.borrow_mut().select_coins_grouped_by_addresses(skip_denominated, anonymizable, skip_unconfirmed, max_outpoints_per_address)
    }

    pub fn get_anonymizable_balance(&mut self, skip_denominated: bool, skip_unconfirmed: bool) -> u64 {
        self.wallet_ex.borrow_mut().get_anonymizable_balance(skip_denominated, skip_unconfirmed)
    }
}

impl CoinJoinClientManager {


    pub fn updated_success_block(&self) {
        self.provider.update_success_block()
    }

    pub fn get_mn_list(&self) -> MasternodeList {
        self.provider.get_current_masternode_list()
    }

    fn mark_already_joined_queue_as_tried(&mut self, pro_tx_hash: &ProTxHash) -> bool {
        for session in self.deq_sessions.iter_mut() {
            if let Some(mn_mixing) = &session.mixing_masternode {
                if pro_tx_hash.eq(&mn_mixing.masternode_list_entry.pro_reg_tx_hash) {
                    return true;
                }
            }
        }
        false
    }
    fn try_submit_denominate(&mut self, mn_addr: SocketAddr) -> bool {
        for session in self.deq_sessions.iter_mut() {
            if let Some(mn_mixing) = &session.mixing_masternode {
                if mn_mixing.masternode_list_entry.service_address == mn_addr && session.base_session.state == PoolState::Queue {
                    session.submit_denominate();
                    return true;
                } else {
                    log_debug!(target: "CoinJoin", "mixingMasternode {} != mnAddr {} or {:?} != {:?}", mn_mixing.masternode_list_entry.service_address, mn_addr, session.base_session.state, PoolState::Queue);
                }
            } else {
                log_debug!(target: "CoinJoin", "mixingMasternode is None");
            }
        }

        false
    }
    fn get_valid_mns_count(&self, mn_list: &MasternodeList) -> usize {
        mn_list.masternodes.values().filter(|mn| mn.masternode_list_entry.is_valid).count()
    }

    fn check_timeout(&mut self) {
        if !self.options.borrow().enable_coinjoin || !self.is_mixing {
            return;
        }

        let mut indices_to_remove = Vec::new();
        
        for (index, session) in self.deq_sessions.iter_mut().enumerate() {
            if session.check_timeout() {
                self.str_auto_denom_result = "Session timed out.".to_string();
                
                if self.is_shutting_down {
                    indices_to_remove.push(index);
                }
            }

            if self.is_shutting_down && 
                (session.base_session.status == PoolStatus::Complete || 
                 session.base_session.status == PoolStatus::Finished || 
                 session.base_session.status == PoolStatus::Timeout ||
                 session.base_session.status == PoolStatus::ConnectionTimeout ||
                 session.base_session.status.is_error()) {
                indices_to_remove.push(index);
            }
        }
        
        for index in indices_to_remove.into_iter().rev() {
            self.deq_sessions.remove(index);
        }

        if self.is_shutting_down && self.deq_sessions.len() == 0 {
            self.trigger_mixing_finished();
        }
    }

    fn trigger_mixing_finished(&mut self) {
        if self.stop_on_nothing_to_do {
            self.mixing_finished = true;
            self.queue_mixing_lifecycle_listeners(true, false);
        }
    }

    fn queue_mixing_lifecycle_listeners(&self, is_complete: bool, is_interrupted: bool) {
        let statuses: Vec<PoolStatus> = self.deq_sessions.iter().map(|x| x.base_session.status).collect();
        self.provider.queue_mixing_lifecycle(is_complete, is_interrupted, statuses);
    }

    pub fn check_queue(&mut self) {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.coinjoin_queue.retain(|q| !q.is_time_out_of_bounds(current_time));
    }

    pub fn get_queue_item_and_try(&mut self) -> Option<CoinJoinQueueMessage> {
        for dsq in self.coinjoin_queue.iter_mut() {
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if !dsq.tried && !dsq.is_time_out_of_bounds(current_time) {
                dsq.tried = true;
                return Some(dsq.clone());
            }
        }
        None
    }

}
