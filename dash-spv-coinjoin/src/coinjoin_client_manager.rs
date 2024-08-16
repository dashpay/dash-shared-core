use dash_spv_masternode_processor::{common::{Block, SocketAddress}, crypto::UInt256, ffi::from::FromFFI, models::{MasternodeEntry, MasternodeList}, secp256k1::rand::{self, seq::SliceRandom, thread_rng, Rng}};
use std::{cell::RefCell, collections::VecDeque, ffi::c_void, rc::Rc, time::{SystemTime, UNIX_EPOCH}};
use crate::{coinjoin::CoinJoin, coinjoin_client_queue_manager::CoinJoinClientQueueManager, coinjoin_client_session::CoinJoinClientSession, constants::{COINJOIN_AUTO_TIMEOUT_MAX, COINJOIN_AUTO_TIMEOUT_MIN}, ffi::callbacks::{DestroyMasternodeList, GetMasternodeList, IsWaitingForNewBlock, UpdateSuccessBlock}, messages::{coinjoin_message::CoinJoinMessage, CoinJoinQueueMessage, PoolState, PoolStatus}, models::{tx_outpoint::TxOutPoint, Balance, CoinJoinClientOptions}, wallet_ex::WalletEx};

pub struct CoinJoinClientManager {
    wallet_ex: Rc<RefCell<WalletEx>>,
    coinjoin: Rc<RefCell<CoinJoin>>,
    pub queue_queue_manager: Option<Rc<RefCell<CoinJoinClientQueueManager>>>,
    options: CoinJoinClientOptions,
    masternodes_used: Vec<UInt256>,
    last_masternode_used: usize,
    last_time_report_too_recent: u64,
    tick: i32,
    do_auto_next_run: i32,
    is_mixing: bool,
    deq_sessions: VecDeque<CoinJoinClientSession>,
    continue_mixing_on_status: Vec<PoolStatus>,
    str_auto_denom_result: String,
    stop_on_nothing_to_do: bool,
    mixing_finished: bool,
    get_masternode_list: GetMasternodeList,
    destroy_mn_list: DestroyMasternodeList,
    update_success_block: UpdateSuccessBlock,
    is_waiting_for_new_block: IsWaitingForNewBlock,
    context: *const c_void
}

impl CoinJoinClientManager {
    pub fn new(
        wallet_ex: Rc<RefCell<WalletEx>>,
        coinjoin: Rc<RefCell<CoinJoin>>,
        options: CoinJoinClientOptions,
        get_masternode_list: GetMasternodeList,
        destroy_mn_list: DestroyMasternodeList, 
        update_success_block: UpdateSuccessBlock,
        is_waiting_for_new_block: IsWaitingForNewBlock,
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
            deq_sessions: VecDeque::new(),
            continue_mixing_on_status: vec![],
            str_auto_denom_result: String::new(),
            stop_on_nothing_to_do: false,
            mixing_finished: false,
            get_masternode_list,
            destroy_mn_list,
            update_success_block,
            is_waiting_for_new_block,
            context
        }
    }

    pub fn set_client_queue_manager(&mut self, queue_queue_manager: Rc<RefCell<CoinJoinClientQueueManager>>) {
        self.queue_queue_manager = Some(queue_queue_manager);
    }

    pub fn process_message(&mut self, from: SocketAddress, message: CoinJoinMessage) {
        println!("[RUST] CoinJoin: process_message");

        if !self.options.enable_coinjoin {
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
        // self.queue_mixing_started_listeners(); TODO
        
        if !self.is_mixing {
            self.is_mixing = true;
            return true;
        }

        return false;
    }

    pub fn set_stop_on_nothing_to_do(&mut self, stop: bool) {
        self.stop_on_nothing_to_do = stop;
    }

    pub fn stop_mixing(&mut self) {
        self.is_mixing = false;
    }

    pub fn do_maintenance(&mut self, balance_info: Balance) {
        println!("[RUST] CoinJoin do_maintenance, sessions len: {}", self.deq_sessions.len());

        if !self.options.enable_coinjoin {
            println!("[RUST] CoinJoin: not enabled");
            return;
        }

        if !self.wallet_ex.borrow().is_synced() {
            println!("[RUST] CoinJoin: not synced");
            return;
        }

        if let Some(queue_manager) = &self.queue_queue_manager {
            queue_manager.borrow_mut().do_maintenance();
        }

        println!("[RUST] CoinJoin: proceed with do_maintenance");
        self.tick += 1;
        self.check_timeout();
        self.process_pending_dsa_request();

        if self.do_auto_next_run >= self.tick {
            self.do_automatic_denominating(balance_info, false);
            let mut rng = rand::thread_rng();
            self.do_auto_next_run = self.tick + COINJOIN_AUTO_TIMEOUT_MIN + rng.gen_range(0..COINJOIN_AUTO_TIMEOUT_MAX - COINJOIN_AUTO_TIMEOUT_MIN);
        }

        // are all sessions idle?
        let mut is_idle = !self.deq_sessions.is_empty(); // false if no sessions created yet
        println!("[RUST] CoinJoin: is_idle? {}", is_idle);
        
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

    pub fn do_automatic_denominating(&mut self, balance_info: Balance, dry_run: bool) -> bool {
        if !self.options.enable_coinjoin || (!dry_run && !self.is_mixing) {
            return false;
        }

        if !self.wallet_ex.borrow().is_synced() {
            println!("[RUST] CoinJoin: wallet is not synced.");
            self.str_auto_denom_result = "Wallet is not synced.".to_string();
            return false;
        }

        // TODO: recheck
        // if (!dryRun && mixingWallet.isEncrypted() && context.coinJoinManager.requestKeyParameter(mixingWallet) == null) {
        //     strAutoDenomResult = "Wallet is locked.";
        //     return false;
        // }

        let mn_count_enabled = self.get_valid_mns_count(&self.get_mn_list());

        // If we've used 90% of the Masternode list then drop the oldest first ~30%
        let threshold_high = (mn_count_enabled as f64 * 0.9) as usize;
        let threshold_low = (threshold_high as f64 * 0.7) as usize;

        if !self.is_waiting_for_new_block() {
            if self.masternodes_used.len() != self.last_masternode_used {
                println!("[RUST] CoinJoin: Checking masternodesUsed: size: {}, threshold: {}", self.masternodes_used.len(), threshold_high);
                self.last_masternode_used = self.masternodes_used.len();
            }
        }

        if self.masternodes_used.len() > threshold_high {
            // remove the first masternodesUsed.size() - thresholdLow masternodes
            // this might be a problem for SPV
            self.masternodes_used.drain(0..(self.masternodes_used.len() - threshold_low));
            println!("[RUST] CoinJoin: masternodesUsed: new size: {}, threshold: {}", self.masternodes_used.len(), threshold_high);
        }

        if let Some(queue_manager) = &self.queue_queue_manager {  
            let mut result = true;

            if self.deq_sessions.len() < self.options.coinjoin_sessions as usize {
                let new_session = CoinJoinClientSession::new(self.coinjoin.clone(), self.options.clone(), self.wallet_ex.clone(), queue_manager.clone());
                println!("[RUST] CoinJoin: creating new session, current amount {}: ", self.deq_sessions.len());

                // TODO:
                // for (ListenerRegistration<SessionCompleteListener> listener : sessionCompleteListeners) {
                //     newSession.addSessionCompleteListener(listener.executor, listener.listener);
                // }
                // for (ListenerRegistration<SessionStartedListener> listener : sessionStartedListeners) {
                //     newSession.addSessionStartedListener(listener.executor, listener.listener);
                // }
                // for (ListenerRegistration<CoinJoinTransactionListener> listener : transactionListeners) {
                //     newSession.addTransationListener (listener.executor, listener.listener);
                // }

                self.deq_sessions.push_back(new_session);
            }

            let mut sessions_to_process: Vec<_> = self.deq_sessions.drain(..).collect();

            for session in sessions_to_process.iter_mut() {
                //     if (!checkAutomaticBackup()) return false;

                // (DashJ) we may not need this
                if !dry_run && self.is_waiting_for_new_block() {
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                            
                    if current_time - self.last_time_report_too_recent > 15_000 {
                        self.str_auto_denom_result = "Last successful action was too recent.".to_string();
                        println!("[RUST] CoinJoin do_automatic_denominating {}", self.str_auto_denom_result);
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

        return false;
    }
    
    pub fn finish_automatic_denominating(&mut self, client_session_id: UInt256) -> bool {
        let mut sessions: Vec<_> = self.deq_sessions.drain(..).collect();
        let mut finished = false;
    
        for session in &mut sessions {
            if session.id == client_session_id {
                finished = session.finish_automatic_denominating(self);
                break;
            }
        }
    
        self.deq_sessions.extend(sessions);
    
        return finished;
    }

    pub fn add_used_masternode(&mut self, pro_tx_hash: UInt256) {
        self.masternodes_used.push(pro_tx_hash);
    }

    pub fn get_random_not_used_masternode(&self) -> Option<MasternodeEntry> {
        let mn_list = self.get_mn_list();
        let count_enabled = self.get_valid_mns_count(&mn_list);
        let count_not_excluded = count_enabled - self.masternodes_used.len();
        println!("[RUST] CoinJoin: {} enabled masternodes, {} masternodes to choose from", count_enabled, count_not_excluded);
        
        if count_not_excluded < 1 {
            return None;
        }

        // fill a vector
        let mut vp_masternodes_shuffled: Vec<&MasternodeEntry> = Vec::with_capacity(count_enabled);
        mn_list.masternodes.values().filter(|mn| mn.is_valid).for_each(|mn| {
            vp_masternodes_shuffled.push(mn);
        });

        // shuffle pointers
        let mut rng = thread_rng();
        vp_masternodes_shuffled.shuffle(&mut rng);

        // loop through
        for dmn in vp_masternodes_shuffled {
            if self.masternodes_used.contains(&dmn.provider_registration_transaction_hash) {
                continue;
            }

            println!("[RUST] CoinJoin: found, masternode={}", dmn.provider_registration_transaction_hash);
            return Some(dmn.clone());
        }

        println!("[RUST] CoinJoin: failed get_random_not_used_masternode");
        return None;
    }

    pub fn updated_success_block(&mut self) {
        unsafe {
            (self.update_success_block)(self.context);
        }
    }

    pub fn get_mn_list(&self) -> MasternodeList {
        unsafe {
            let raw_mn_list = (self.get_masternode_list)(self.context);
            let mn_list = (*raw_mn_list).decode();
            (self.destroy_mn_list)(raw_mn_list);

            mn_list
        }
    }

    pub fn process_pending_dsa_request(&mut self) {
        for session in self.deq_sessions.iter_mut() {
            if session.process_pending_dsa_request() {
                self.str_auto_denom_result = "Mixing in progress...".to_string();
            } else {
                println!("[RUST] CoinJoin dsa: did not process pending dsa request");
            }
        }
    }

    pub fn get_sessions_status(&self) -> Vec<PoolStatus> {
        let mut sessions_status = Vec::new();
        
        for session in self.deq_sessions.iter() {
            sessions_status.push(session.base_session.status);
        }
        
        return sessions_status;
    }

    pub fn is_waiting_for_new_block(&self) -> bool {
        if self.options.coinjoin_multi_session {
            return false;
        }

        return unsafe { (self.is_waiting_for_new_block)(self.context) };
    }

    pub fn try_submit_denominate(&mut self, mn_addr: SocketAddress) -> bool {
        println!("[RUST] CoinJoin dsi: try_submit_denominate, address: {}", mn_addr);

        for session in self.deq_sessions.iter_mut() {
            if let Some(mn_mixing) = &session.mixing_masternode {
                if mn_mixing.socket_address == mn_addr && session.base_session.state == PoolState::Queue {
                    session.submit_denominate();
                    return true;
                } else {
                    println!("[RUST] CoinJoin dsi: mixingMasternode {} != mnAddr {} or {:?} != {:?}", mn_mixing.socket_address, mn_addr, session.base_session.state, PoolState::Queue);
                }
            } else {
                println!("[RUST] CoinJoin dsi: mixingMasternode is None");
            }
        }

        return false;
    }

    pub fn mark_already_joined_queue_as_tried(&mut self, dsq: &mut CoinJoinQueueMessage) -> bool {
        for session in self.deq_sessions.iter_mut() {
            if let Some(mn_mixing) = &session.mixing_masternode {
                if mn_mixing.provider_registration_transaction_hash == dsq.pro_tx_hash {
                    dsq.tried = true;
                    return true;
                }
            }
        }

        return false;
    }

    pub fn update_block_tip(&mut self, block: Block) {
        self.coinjoin.borrow_mut().update_block_tip(block)
    }

    pub fn is_fully_mixed(&mut self, outpoint: TxOutPoint) -> bool {
        return self.wallet_ex.borrow_mut().is_fully_mixed(outpoint);
    }

    fn get_valid_mns_count(&self, mn_list: &MasternodeList) -> usize {
        mn_list.masternodes.values().filter(|mn| mn.is_valid).count()
    }

    fn check_timeout(&mut self) {
        if !self.options.enable_coinjoin || !self.is_mixing {
            return;
        }

        for session in self.deq_sessions.iter_mut() {
            if session.check_timeout() {
                self.str_auto_denom_result = "Session timed out.".to_string();
            }
        }
    }

    fn trigger_mixing_finished(&mut self) {
        println!("[RUST] CoinJoin: trigger_mixing_finished");
        if self.stop_on_nothing_to_do {
            self.mixing_finished = true;
            // TODO: self.queue_mixing_complete_listeners();
        }
    }
}
