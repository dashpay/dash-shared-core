use dash_spv_masternode_processor::{crypto::UInt256, ffi::from::FromFFI, models::{MasternodeEntry, MasternodeList}, secp256k1::rand::{self, seq::SliceRandom, thread_rng, Rng}};
use std::{cell::RefCell, collections::{HashSet, VecDeque}, ffi::c_void, rc::Rc};

use crate::{coinjoin::CoinJoin, coinjoin_client_session::CoinJoinClientSession, constants::{COINJOIN_AUTO_TIMEOUT_MAX, COINJOIN_AUTO_TIMEOUT_MIN}, ffi::callbacks::{DestroyMasternodeList, GetMasternodeList}, messages::PoolStatus, models::{Balance, CoinJoinClientOptions}, wallet_ex::WalletEx};

pub struct CoinJoinClientManager {
    wallet_ex: Rc<RefCell<WalletEx>>,
    coinjoin: Rc<RefCell<CoinJoin>>,
    options: CoinJoinClientOptions,
    masternodes_used: HashSet<UInt256>,
    cached_last_success_block: i32,
    cached_block_height: i32, // Keep track of current block height
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
    context: *const c_void
}

impl CoinJoinClientManager {
    pub fn new(
        wallet_ex: Rc<RefCell<WalletEx>>,
        coinjoin: Rc<RefCell<CoinJoin>>,
        options: CoinJoinClientOptions,
        get_masternode_list: GetMasternodeList,
        destroy_mn_list: DestroyMasternodeList, 
        context: *const c_void
    ) -> Self {
        Self {
            wallet_ex,
            coinjoin,
            options,
            masternodes_used: HashSet::new(),
            cached_last_success_block: 0,
            cached_block_height: 0,
            tick: 0,
            do_auto_next_run: COINJOIN_AUTO_TIMEOUT_MIN, // TODO: this and tick should be static
            is_mixing: false,
            deq_sessions: VecDeque::new(),
            continue_mixing_on_status: vec![],
            str_auto_denom_result: String::new(),
            stop_on_nothing_to_do: false,
            mixing_finished: false,
            get_masternode_list,
            destroy_mn_list,
            context
        }
    }

    pub fn do_maintenance(&mut self, balance_info: Balance) {
        if !self.options.enable_coinjoin {
            println!("[RUST] CoinJoin: not enabled");
            return;
        }

        if !self.wallet_ex.borrow().is_synced() {
            println!("[RUST] CoinJoin: not synced");
            return;
        }

        println!("[RUST] CoinJoin: proceed with do_maintenance");
        self.tick += 1;
        self.check_timeout();
        self.process_pending_dsa_request();

        if self.do_auto_next_run >= self.tick {
            println!("[RUST] CoinJoin: do_auto_next_run >= tick");
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

    pub fn do_automatic_denominating(&mut self, balance_info: Balance, dry_run: bool) -> u64 {
        // TODO: finish method

        let mut session = CoinJoinClientSession::new(self.coinjoin.clone(), self.options.clone(), self.wallet_ex.clone());
        let result = session.do_automatic_denominating(self, dry_run, balance_info);
        self.deq_sessions.push_back(session);
        
        return result;
    }
    pub fn finish_automatic_denominating(&mut self, balance_denominated_unconf: u64, balance_needs_anonymized: u64) -> bool {
        if let Some(mut session) = self.deq_sessions.pop_back() {
            session.finish_automatic_denominating(self, balance_denominated_unconf, balance_needs_anonymized);
            self.deq_sessions.push_back(session);

            return true
        }

        return false;
    }
    pub fn add_used_masternode(&mut self, pro_tx_hash: UInt256) {
        self.masternodes_used.insert(pro_tx_hash);
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
        self.cached_last_success_block = self.cached_block_height;
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
            // self.queue_mixing_complete_listeners();
        }
    }
}
