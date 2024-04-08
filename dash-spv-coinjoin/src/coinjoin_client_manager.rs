use dash_spv_masternode_processor::{crypto::UInt256, ffi::from::FromFFI, models::{MasternodeEntry, MasternodeList}, secp256k1::rand::{seq::SliceRandom, thread_rng}};
use std::{cell::RefCell, collections::{HashSet, VecDeque}, ffi::c_void, rc::Rc};

use crate::{coinjoin::CoinJoin, coinjoin_client_session::CoinJoinClientSession, ffi::callbacks::{DestroyMasternodeList, GetMasternodeList}, models::CoinJoinClientOptions, wallet_ex::WalletEx};

pub struct CoinJoinClientManager {
    wallet_ex: Rc<RefCell<WalletEx>>,
    coinjoin: Rc<RefCell<CoinJoin>>,
    options: CoinJoinClientOptions,
    masternodes_used: HashSet<UInt256>,
    cached_last_success_block: i32,
    cached_block_height: i32, // Keep track of current block height
    deq_sessions: VecDeque<CoinJoinClientSession>,
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
            deq_sessions: VecDeque::new(),
            get_masternode_list,
            destroy_mn_list,
            context
        }
    }

    pub fn do_automatic_denominating(&mut self, balance_info: crate::models::Balance, dry_run: bool) -> u64 {
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

        println!("[RUST] CoinJoin:  {} enabled masternodes, {} masternodes to choose from", count_enabled, count_not_excluded);
        
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

    fn get_valid_mns_count(&self, mn_list: &MasternodeList) -> usize {
        mn_list.masternodes.values().filter(|mn| mn.is_valid).count()
    }
}
