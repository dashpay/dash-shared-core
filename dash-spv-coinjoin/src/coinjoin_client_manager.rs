use std::{cell::RefCell, collections::VecDeque, ffi::c_void, rc::Rc, time::{SystemTime, UNIX_EPOCH}};
use std::net::SocketAddr;
use std::sync::Arc;
use dashcore::hashes::Hash;
use dashcore::prelude::DisplayHex;
use dashcore::secp256k1::rand::{thread_rng, Rng};
use dashcore::secp256k1::rand::prelude::SliceRandom;
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dashcore::{OutPoint, Transaction, Txid};
use dash_spv_masternode_processor::common::Block;
use logging::*;
use crate::{coinjoin::CoinJoin, coinjoin_client_queue_manager::CoinJoinClientQueueManager, coinjoin_client_session::CoinJoinClientSession, constants::{COINJOIN_AUTO_TIMEOUT_MAX, COINJOIN_AUTO_TIMEOUT_MIN}, messages::{coinjoin_message::CoinJoinMessage, CoinJoinQueueMessage, PoolState, PoolStatus}, models::{Balance, CoinJoinClientOptions}, wallet_ex::WalletEx};
use crate::messages::PoolMessage;

// #[ferment_macro::opaque]
pub struct CoinJoinClientManager {
    pub wallet_ex: Rc<RefCell<WalletEx>>,
    coinjoin: Rc<RefCell<CoinJoin>>,
    pub queue_queue_manager: Option<Rc<RefCell<CoinJoinClientQueueManager>>>,
    options: Rc<RefCell<CoinJoinClientOptions>>,
    masternodes_used: Vec<[u8; 32]>,
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
    get_masternode_list: Arc<dyn Fn(*const c_void) -> MasternodeList>,
    // destroy_mn_list: DestroyMasternodeList,
    update_success_block: Arc<dyn Fn(*const c_void)>,
    is_waiting_for_new_block: Arc<dyn Fn(*const c_void) -> bool>,
    session_lifecycle_listener: Arc<dyn Fn(*const c_void, bool, i32, [u8; 32], u32, PoolState, PoolMessage, PoolStatus, bool)>,
    mixing_lifecycle_listener: Arc<dyn Fn(*const c_void, bool, bool, Vec<PoolStatus>)>,
    context: *const c_void
}

impl CoinJoinClientManager {
    pub fn new<
        GML: Fn(*const c_void) -> MasternodeList + 'static,
        USB: Fn(*const c_void) + 'static,
        IWFNB: Fn(*const c_void) -> bool + 'static,
        SLL: Fn(*const c_void, bool, i32, [u8; 32], u32, PoolState, PoolMessage, PoolStatus, bool) + 'static,
        MLL: Fn(*const c_void, bool, bool, Vec<PoolStatus>) + 'static,
    >(
        wallet_ex: Rc<RefCell<WalletEx>>,
        coinjoin: Rc<RefCell<CoinJoin>>,
        options: Rc<RefCell<CoinJoinClientOptions>>,
        get_masternode_list: GML,
        // destroy_mn_list: DestroyMasternodeList,
        update_success_block: USB,
        is_waiting_for_new_block: IWFNB,
        session_lifecycle_listener: SLL,
        mixing_lifecycle_listener: MLL,
        context: *const c_void
    ) -> Self {
        Self {
            wallet_ex,
            coinjoin,
            queue_queue_manager: None,
            options,
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
            get_masternode_list: Arc::new(get_masternode_list),
            update_success_block: Arc::new(update_success_block),
            is_waiting_for_new_block: Arc::new(is_waiting_for_new_block),
            session_lifecycle_listener: Arc::new(session_lifecycle_listener),
            mixing_lifecycle_listener: Arc::new(mixing_lifecycle_listener),
            context
        }
    }

    pub fn set_client_queue_manager(&mut self, queue_queue_manager: Rc<RefCell<CoinJoinClientQueueManager>>) {
        self.queue_queue_manager = Some(queue_queue_manager);
    }

    pub fn process_message(&mut self, from: SocketAddr, message: CoinJoinMessage) {
        if !self.options.borrow().enable_coinjoin {
            return;
        }

        if !self.wallet_ex.borrow().is_synced() {
            return;
        }

        if let CoinJoinMessage::BroadcastTx(broadcast_tx) = message {
            self.coinjoin.borrow_mut().add_dstx(broadcast_tx.clone());
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

        if let Some(queue_manager) = &self.queue_queue_manager {
            queue_manager.borrow_mut().do_maintenance();
        }

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

        if let Some(queue_manager) = &self.queue_queue_manager {
            queue_manager.borrow_mut().set_null();
        }
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

        if let Some(queue_manager) = &self.queue_queue_manager {
            let mut result = true;
            
            if self.deq_sessions.len() < self.options.borrow().coinjoin_sessions as usize {
                let new_session = CoinJoinClientSession::new(
                    self.coinjoin.clone(),
                    self.options.clone(),
                    self.wallet_ex.clone(),
                    queue_manager.clone(),
                    self.session_lifecycle_listener.clone(),
                    self.context
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

            return result;
        }
        
        false
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

    pub fn add_used_masternode(&mut self, pro_tx_hash: [u8; 32]) {
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
            if self.masternodes_used.contains(&dmn.masternode_list_entry.pro_reg_tx_hash.as_byte_array()) {
                continue;
            }

            log_info!(target: "CoinJoin", "mn found, proTxHash={}", dmn.masternode_list_entry.pro_reg_tx_hash.as_byte_array().to_lower_hex_string());
            return Some(dmn.clone());
        }

        log_error!(target: "CoinJoin", "failed get_random_not_used_masternode");
        None
    }

    pub fn updated_success_block(&mut self) {
        unsafe {
            (self.update_success_block)(self.context);
        }
    }

    pub fn get_mn_list(&self) -> MasternodeList {
        (self.get_masternode_list)(self.context)
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
        (self.is_waiting_for_new_block)(self.context)
    }

    pub fn try_submit_denominate(&mut self, mn_addr: SocketAddr) -> bool {
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

    pub fn mark_already_joined_queue_as_tried(&mut self, dsq: &mut CoinJoinQueueMessage) -> bool {
        for session in self.deq_sessions.iter_mut() {
            if let Some(mn_mixing) = &session.mixing_masternode {
                if dsq.pro_tx_hash.eq(mn_mixing.masternode_list_entry.pro_reg_tx_hash.as_byte_array()) {
                    dsq.tried = true;
                    return true;
                }
            }
        }
        false
    }

    pub fn update_block_tip(&mut self, block: Block) {
        self.coinjoin.borrow_mut().update_block_tip(block)
    }

    pub fn is_mixing_fee_tx(&self, tx_id: &Txid) -> bool {
        for session in &self.deq_sessions {
            if session.is_mixing_fee_tx(tx_id) {
                return true;
            }
        }
        false
    }

    pub fn refresh_unused_keys(&mut self) {
        self.wallet_ex.borrow_mut().refresh_unused_keys();
    }

    pub fn process_used_scripts(&mut self, scripts: &Vec<Vec<u8>>) {
        self.wallet_ex.borrow_mut().process_used_scripts(scripts);
    }

    pub fn change_options(&mut self, new_options: CoinJoinClientOptions) {
        if new_options != *self.options.borrow() {
            if self.options.borrow().enable_coinjoin || new_options.enable_coinjoin {
                log_info!(target: "CoinJoin", "updating client options: {:?}", new_options);
            }
            *self.options.borrow_mut() = new_options.clone();
        }
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
        let mut len = self.deq_sessions.len();

        println!("[RUST] CoinJoin: sessions {:?}", len);
        for session in self.deq_sessions.iter() {
            println!("[RUST] CoinJoin: session status: {:?}", session.base_session.status);
        }

        len
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
        (self.mixing_lifecycle_listener)(self.context, is_complete, is_interrupted, statuses);
        //
        //
        // let length = statuses.len();
        //
        // unsafe {
        //     let boxed_statuses = boxed_vec(statuses);
        //     (self.mixing_lifecycle_listener)(is_complete, is_interrupted, boxed_statuses, length, self.context);
        //     unbox_vec_ptr(boxed_statuses, length);
        // }
    }
}
