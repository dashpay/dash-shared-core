use std::cell::RefCell;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::rc::Rc;
use std::time::{SystemTime, UNIX_EPOCH};
use logging::*;
use tracing::{info, warn, error, debug};
use dash_spv_masternode_processor::blockdata::opcodes::all::OP_RETURN;
use dash_spv_masternode_processor::chain::params::DUFFS;
use dash_spv_masternode_processor::chain::tx::protocol::{TXIN_SEQUENCE, TX_UNCONFIRMED};
use dash_spv_masternode_processor::common::SocketAddress;
use dash_spv_masternode_processor::consensus::Encodable;
use dash_spv_masternode_processor::crypto::byte_util::{Random, Reversable};
use dash_spv_masternode_processor::crypto::{UInt128, UInt256};
use dash_spv_masternode_processor::ffi::boxer::boxed;
use dash_spv_masternode_processor::ffi::unboxer::unbox_any;
use dash_spv_masternode_processor::models::MasternodeEntry;
use dash_spv_masternode_processor::secp256k1::rand::{self, Rng};
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use dash_spv_masternode_processor::util::script::ScriptType;

use crate::coinjoin::CoinJoin;
use crate::coinjoin_client_manager::CoinJoinClientManager;
use crate::coinjoin_client_queue_manager::CoinJoinClientQueueManager;
use crate::constants::{COINJOIN_DENOM_OUTPUTS_THRESHOLD, COINJOIN_ENTRY_MAX_SIZE, COINJOIN_QUEUE_TIMEOUT, COINJOIN_SIGNING_TIMEOUT, DEFAULT_COINJOIN_DENOMS_GOAL, DEFAULT_COINJOIN_DENOMS_HARDCAP};
use crate::ffi::callbacks::SessionLifecycleListener;
use crate::messages::{CoinJoinAcceptMessage, CoinJoinCompleteMessage, CoinJoinEntry, CoinJoinFinalTransaction, CoinJoinSignedInputs, CoinJoinStatusUpdate, PoolMessage, PoolStatusUpdate};
use crate::models::coin_control::{CoinControl, CoinType};
use crate::models::coinjoin_transaction_input::CoinJoinTransactionInput;
use crate::models::reserve_destination::ReserveDestination;
use crate::models::tx_outpoint::TxOutPoint;
use crate::messages::{pool_state::PoolState, pool_status::PoolStatus};
use crate::models::pending_dsa_request::PendingDsaRequest;
use crate::models::{CoinJoinClientOptions, Balance};
use crate::coinjoin_base_session::CoinJoinBaseSession;
use crate::utils::coin_format::CoinFormat;
use crate::utils::key_holder_storage::KeyHolderStorage;
use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::utils::transaction_builder::TransactionBuilder;
use crate::wallet_ex::WalletEx;
use crate::messages::coinjoin_message::{CoinJoinMessageType, CoinJoinMessage};

pub struct CoinJoinClientSession {
    pub id: UInt256,
    coinjoin: Rc<RefCell<CoinJoin>>,
    mixing_wallet: Rc<RefCell<WalletEx>>,
    queue_manager: Rc<RefCell<CoinJoinClientQueueManager>>,
    pub base_session: CoinJoinBaseSession,
    options: Rc<RefCell<CoinJoinClientOptions>>,
    key_holder_storage: KeyHolderStorage,
    last_create_denominated_result: bool,
    outpoint_locked: Vec<TxOutPoint>,
    pub mixing_masternode: Option<MasternodeEntry>,
    pending_dsa_request: Option<PendingDsaRequest>,
    tx_my_collateral: Option<Transaction>,
    is_my_collateral_valid: bool,
    collateral_session_map: HashMap<UInt256, i32>,
    balance_needs_anonymized: u64,
    joined: bool, // did we join a session (true), or start a session (false)
    pub has_nothing_to_do: bool,
    str_auto_denom_result: String,
    str_last_message: String,
    session_lifecycle_listener: SessionLifecycleListener,
    context: *const c_void
}

impl CoinJoinClientSession {
    pub fn new(
        coinjoin: Rc<RefCell<CoinJoin>>,
        options: Rc<RefCell<CoinJoinClientOptions>>,
        wallet_ex: Rc<RefCell<WalletEx>>,
        client_queue_manager: Rc<RefCell<CoinJoinClientQueueManager>>,
        session_lifecycle_listener: SessionLifecycleListener,
        context: *const c_void
    ) -> Self {
        Self {
            id: UInt256::random(),
            coinjoin: coinjoin,
            mixing_wallet: wallet_ex,
            queue_manager: client_queue_manager,
            base_session: CoinJoinBaseSession::new(),
            key_holder_storage: KeyHolderStorage::new(),
            options: options,
            last_create_denominated_result: true,
            outpoint_locked: Vec::new(),
            mixing_masternode: None,
            pending_dsa_request: None,
            tx_my_collateral: None,
            is_my_collateral_valid: false,
            collateral_session_map: HashMap::new(),
            balance_needs_anonymized: 0,
            joined: false,
            has_nothing_to_do: false,
            str_auto_denom_result: String::new(),
            str_last_message: String::new(),
            session_lifecycle_listener,
            context
        }
    }

    pub fn do_automatic_denominating(&mut self, client_manager: &mut CoinJoinClientManager, dry_run: bool, balance_info: Balance) -> bool {
        if self.base_session.state != PoolState::Idle || !self.options.borrow().enable_coinjoin {
            return false;
        }

        if self.base_session.entries.len() > 0 {
            self.set_status(PoolStatus::Mixing);
            return false;
        }

        if self.options.borrow().coinjoin_amount == 0 || balance_info.my_trusted == 0 {
            log_debug!(target: "CoinJoin", "CoinJoinClientSession::do_automatic_denominating -- skipping");
            return false;
        }

        log_info!(target: "CoinJoin", "balance: {}, coinjoin_amount: {}", balance_info, self.options.borrow().coinjoin_amount);

        let balance_anonymized = balance_info.anonymized;
        let sub_res = self.options.borrow().coinjoin_amount.checked_sub(balance_anonymized);
        
        if sub_res.is_none() || sub_res.unwrap() == 0 {
            log_info!(target: "CoinJoin", "CoinJoinClientSession::do_automatic_denominating -- Nothing to do");
            // nothing to do, just keep it in idle mode
            self.set_status(PoolStatus::Finished);
            return false;
        }

        let mut balance_needs_anonymized = sub_res.unwrap();
        let mut value_min = CoinJoin::get_smallest_denomination();

        // if there are no confirmed DS collateral inputs yet
        if !self.mixing_wallet.borrow_mut().has_collateral_inputs(true) {
            // should have some additional amount for them
            value_min = value_min + CoinJoin::get_max_collateral_amount();
        }

        // including denoms but applying some restrictions
        let balance_anonymizable = self.mixing_wallet.borrow_mut().get_anonymizable_balance(false, true);

         // mixable balance is way too small
         if balance_anonymizable < value_min {
            let balance_left_to_mix = self.mixing_wallet.borrow_mut().get_anonymizable_balance(false, false);
            
            if !dry_run && balance_left_to_mix < value_min {
                self.set_status(PoolStatus::ErrNotEnoughFunds);
                self.queue_session_lifecycle_listeners(true, self.base_session.state, PoolMessage::ErrSession);
            }
            
            log_info!(target: "CoinJoin", "skipping, balance_anonymizable: {}, balance_left_to_mix: {}, value_min: {}", balance_anonymizable, balance_left_to_mix, value_min);
            return false;
        }

        let balance_anonimizable_non_denom = self.mixing_wallet.borrow_mut().get_anonymizable_balance(true, true);
        let balance_denominated_conf = balance_info.denominated_trusted;
        let balance_denominated_unconf = balance_info.denominated_untrusted_pending;
        let balance_denominated = balance_denominated_conf + balance_denominated_unconf;
        let balance_to_denominate = self.options.borrow().coinjoin_amount.saturating_sub(balance_denominated);
        log_info!(target: "CoinJoin", "balance_to_denominate: {}, dry_run: {}", balance_to_denominate, dry_run);

        // Adjust balance_needs_anonymized to consume final denom
        if balance_denominated.saturating_sub(balance_anonymized) > balance_needs_anonymized as u64 {
            log_info!(target: "CoinJoin", "adjusting balance_needs_anonymized to consume final denom");
            let denoms = CoinJoin::get_standard_denominations();
            let mut additional_denom: u64 = 0;
            
            for denom in denoms {
                if (balance_needs_anonymized as u64) < *denom {
                    additional_denom = *denom;
                } else {
                    break;
                }
            }
            balance_needs_anonymized += additional_denom;
        }

        log_info!(target: "CoinJoin", "current stats: value_min: {}, my_trusted: {}, balance_anonymizable: {}, balance_anonymized: {}, balance_needs_anonymized: {}, balance_anonimizable_non_denom: {}, balance_denominated_conf: {}, balance_denominated_unconf: {}, balance_denominated: {}, balance_to_denominate: {}",
            value_min.to_friendly_string(),
            balance_info.my_trusted.to_friendly_string(),
            balance_anonymizable.to_friendly_string(),
            balance_anonymized.to_friendly_string(),
            balance_needs_anonymized.to_friendly_string(),
            balance_anonimizable_non_denom.to_friendly_string(),
            balance_denominated_conf.to_friendly_string(),
            balance_denominated_unconf.to_friendly_string(),
            balance_denominated.to_friendly_string(),
            balance_to_denominate.to_friendly_string()
        );

        // Check if we have should create more denominated inputs i.e.
        // there are funds to denominate and denominated balance does not exceed
        // max amount to mix yet.
        self.last_create_denominated_result = false;
        
        if balance_anonimizable_non_denom >= value_min + CoinJoin::get_max_collateral_amount() && balance_to_denominate >= CoinJoin::get_smallest_denomination() {
            self.last_create_denominated_result = self.create_denominated(client_manager, balance_to_denominate, dry_run);
        }

        if dry_run {
            if self.last_create_denominated_result {
                self.balance_needs_anonymized = balance_needs_anonymized;
                return true;
            }

            return false;
        }

        self.balance_needs_anonymized = balance_needs_anonymized;

        if self.last_create_denominated_result {
            log_debug!(target: "CoinJoin", "auto_denom: wait for finish callback");
            // If transaction was commited, return and wait for obj-c to call finish_automatic_denominating
            return true;
        } else {
            log_debug!(target: "CoinJoin", "auto_denom: proceed immediately");
            // If no transactions were commited, call finish_automatic_denominating directly
            self.last_create_denominated_result = true;
            self.finish_automatic_denominating(client_manager);

            return true;
        }
    }

    pub fn finish_automatic_denominating(&mut self, client_manager: &mut CoinJoinClientManager) -> bool {
        log_debug!(target: "CoinJoin", "finish_automatic_denominating: {}", self.balance_needs_anonymized.to_friendly_string());

        if self.balance_needs_anonymized == 0 {
            return false;
        }

        let balance_needs_anonymized = self.balance_needs_anonymized;
        self.balance_needs_anonymized = 0;

        // check if we have the collateral sized inputs
        if !self.mixing_wallet.borrow_mut().has_collateral_inputs(true) {
            let result = !self.mixing_wallet.borrow_mut().has_collateral_inputs(false) && self.make_collateral_amounts(client_manager);
            log_info!(target: "CoinJoin", "exiting finish_automatic_denominating early with result: {}", result);
            return result;
        }

        if self.base_session.session_id != 0 {
            self.set_status(PoolStatus::Mixing);
            log_info!(target: "CoinJoin", "base_session.session_id != 0");
            return false;
        }
        
        // Initial phase, find a Masternode
        // Clean if there is anything left from previous session
        self.unlock_coins();
        self.key_holder_storage.return_all();
        self.set_null();

        // should be no unconfirmed denoms in non-multi-session mode
        // TODO: support denominatedUntrustedPending

        // if !self.options.coinjoin_multi_session && balance_denominated_unconf > 0 {
        //     self.str_auto_denom_result = "Found unconfirmed denominated outputs, will wait till they confirm to continue.".to_string();
        //     println!("[RUST] CoinJoin: {}", self.str_auto_denom_result);
        //     return false;
        // }

        let mut reason = String::new();
        match self.tx_my_collateral.clone() {
            None => {
                if !self.create_collateral_transaction(&mut reason) {
                    log_error!(target: "CoinJoin", "create collateral error: {}", reason);
                    return false;
                }
            },
            Some(collateral) => {
                if !self.is_my_collateral_valid || !self.coinjoin.borrow().is_collateral_valid(&collateral, true) {
                    log_info!(target: "CoinJoin", "invalid collateral, recreating... [id: {}] ", self.id);
                    let output = &collateral.outputs[0];
                    
                    if output.script_pub_key_type() == ScriptType::PayToPubkeyHash {
                        self.mixing_wallet.borrow_mut().add_unused_key(&output.script);
                    }

                    if !self.create_collateral_transaction(&mut reason) {
                        log_error!(target: "CoinJoin", "create collateral error: {}", reason);
                        return false;
                    }
                }

                // lock the funds we're going to use for our collateral
                for txin in &collateral.inputs {
                    let outpoint = TxOutPoint::new(txin.input_hash, txin.index);
                    self.mixing_wallet.borrow_mut().lock_coin(outpoint.clone());
                    self.outpoint_locked.push(outpoint);
                }
            }
        }

        if self.options.borrow().denom_only {
            return true;
        }

        // Always attempt to join an existing queue
        if self.join_existing_queue(client_manager, balance_needs_anonymized) {
            return true;
        }

        // If we were unable to find/join an existing queue then start a new one.
        if self.start_new_queue(client_manager, balance_needs_anonymized) {
            return true;
        }
        
        self.set_status(PoolStatus::WarnNoCompatibleMasternode);

        return false;
    }

    pub fn process_pending_dsa_request(&mut self) -> bool {
        if let Some(pending_request) = &self.pending_dsa_request {
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            self.base_session.time_last_successful_step = current_time;
            let mut buffer = vec![];
            pending_request.dsa.consensus_encode(&mut buffer).unwrap();
            let message_sent = self.mixing_wallet.borrow_mut().send_message(buffer, pending_request.dsa.get_message_type(), &pending_request.addr, false);
            
            if message_sent {
                log_info!(target: "CoinJoin", "sent dsa to {}", pending_request.addr);
                log_debug!(target: "CoinJoin", "dsa={}", pending_request.dsa);
                self.pending_dsa_request = None;
            } else if pending_request.is_expired() {
                log_warn!(target: "CoinJoin", "failed to connect to {}; reason: cannot find peer", pending_request.addr);
                self.set_status(PoolStatus::ConnectionTimeout);
                self.queue_session_lifecycle_listeners(true, self.base_session.state, PoolMessage::ErrConnectionTimeout);
                self.set_null();
            }
    
            return message_sent;
        }

        return false;
    }

    fn create_denominated(&mut self, client_manager: &mut CoinJoinClientManager, balance_to_denominate: u64, dry_run: bool) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }
    
        // NOTE: We do not allow txes larger than 100 kB, so we have to limit number of inputs here.
        // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
        // Knowing that each CTxIn is at least 148 B big, 400 inputs should take 400 x ~148 B = ~60 kB.
        // This still leaves more than enough room for another data of typical CreateDenominated tx.
        let mut vec_tally: Vec<CompactTallyItem> = self.mixing_wallet.borrow_mut().select_coins_grouped_by_addresses(true, true, true, 400);
    
        if vec_tally.is_empty() {
            log_info!(target: "CoinJoin", "CoinJoinClientSession::CreateDenominated -- SelectCoinsGroupedByAddresses can't find any inputs!");
            return false;
        }
    
        // Start from the largest balances first to speed things up by creating txes with larger/largest denoms included
        vec_tally.sort_by(|a, b| b.amount.cmp(&a.amount));
        let create_mixing_collaterals = !self.mixing_wallet.borrow_mut().has_collateral_inputs(true);
        log_info!(target: "CoinJoin", "has_collateral_inputs: {}", !create_mixing_collaterals);

        for item in vec_tally {
            if !self.create_denominated_with_item(client_manager, &item, balance_to_denominate, create_mixing_collaterals, dry_run) {
                continue;
            }

            return true;
        }
    
        log_info!(target: "CoinJoin", "CoinJoinClientSession: createDenominated({}) -- failed! ", balance_to_denominate.to_friendly_string());
        false
    }

    fn create_denominated_with_item(
        &mut self,
        client_manager: &mut CoinJoinClientManager,
        tally_item: &CompactTallyItem, 
        balance_to_denominate: u64, 
        create_mixing_collaterals: bool, 
        dry_run: bool
    ) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }

        // denominated input is always a single one, so we can check its amount directly and return early
        if tally_item.input_coins.len() == 1 && CoinJoin::is_denominated_amount(tally_item.amount) {
            return false;
        }

        let mut tx_builder = TransactionBuilder::new(
            self.mixing_wallet.clone(),
            self.options.borrow().chain_type,
            tally_item.clone(),
            dry_run
        );

        log_info!(target: "CoinJoin", "create_denominated_with_item. Start tx_builder: {}", tx_builder);

        // ****** Add an output for mixing collaterals ************ /

        if create_mixing_collaterals && !tx_builder.add_output(CoinJoin::get_max_collateral_amount()) {
            log_warn!(target: "CoinJoin", "CoinJoinClientSession::CreateDenominatedWithItem -- Failed to add collateral output");
            return false;
        }

        // ****** Add outputs for denoms ************ /

        let mut add_final = true;
        let denoms = CoinJoin::get_standard_denominations();
        let mut map_denom_count = HashMap::new();

        for denom_value in denoms {
            map_denom_count.insert(*denom_value, self.mixing_wallet.borrow_mut().count_inputs_with_amount(*denom_value));
        }

        // Will generate outputs for the createdenoms up to coinjoinmaxdenoms per denom

        // This works in the way creating PS denoms has traditionally worked, assuming enough funds,
        // it will start with the smallest denom then create 11 of those, then go up to the next biggest denom create 11
        // and repeat. Previously, once the largest denom was reached, as many would be created were created as possible and
        // then any remaining was put into a change address and denominations were created in the same manner a block later.
        // Now, in this system, so long as we don't reach COINJOIN_DENOM_OUTPUTS_THRESHOLD outputs the process repeats in
        // the same transaction, creating up to nCoinJoinDenomsHardCap per denomination in a single transaction.
        // let tx_builder = self.tx_builder.borrow_mut();

        let mut balance_to_denominate = balance_to_denominate;

        while tx_builder.could_add_output(CoinJoin::get_smallest_denomination()) && (tx_builder.outputs.len() as i32) < COINJOIN_DENOM_OUTPUTS_THRESHOLD {
            for denom_value in denoms.iter().rev() {
                let mut outputs = 0;

                let mut need_more_outputs = |tx_builder: &TransactionBuilder, balance_to_denom: u64, outputs: i32| {
                    if tx_builder.could_add_output(*denom_value) {
                        if add_final && balance_to_denom > 0 && balance_to_denom < *denom_value {
                            add_final = false; // add final denom only once, only the smallest possible one
                            log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 1 - FINAL - nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                                denom_value.to_friendly_string(), balance_to_denom.to_friendly_string(), outputs, tx_builder.to_string());
                            return true;
                        } else if balance_to_denom >= *denom_value {
                            return true;
                        }
                    }
                    
                    return false;
                };

                // add each output up to 11 times or until it can't be added again or until we reach nCoinJoinDenomsGoal
                while need_more_outputs(&tx_builder, balance_to_denominate, outputs) && outputs <= 10 && map_denom_count[denom_value] <  DEFAULT_COINJOIN_DENOMS_GOAL {
                    // Add output and subtract denomination amount
                    if tx_builder.add_output(*denom_value) {
                        outputs += 1;
                        *map_denom_count.entry(*denom_value).or_insert(0) += 1;
                        balance_to_denominate = balance_to_denominate.saturating_sub(*denom_value);
                        log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                            denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                    } else {
                        log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - Error: AddOutput failed for nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                            denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                        return false;
                    }
                }

                log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - tx_builder.amount_left: {}, balance_to_denominate: {}", tx_builder.amount_left(), balance_to_denominate);
                if tx_builder.amount_left() == 0 || balance_to_denominate == 0 {
                    break;
                }
            }

            let mut finished = true;

            for (denom, count) in &map_denom_count {
                // Check if this specific denom could use another loop, check that there aren't nCoinJoinDenomsGoal of this
                // denom and that our nValueLeft/nBalanceToDenominate is enough to create one of these denoms, if so, loop again.
                if *count < DEFAULT_COINJOIN_DENOMS_GOAL && tx_builder.could_add_output(*denom) && balance_to_denominate >= CoinJoin::get_smallest_denomination() {
                    finished = false;
                    log_info!(target: "CoinJoin", "CoinJoinClientSession -- 1 - NOT finished - nDenomValue: {}, count: {}, nBalanceToDenominate: {}, {}",
                        denom.to_friendly_string(), count, balance_to_denominate.to_friendly_string(), tx_builder.to_string());
                    break;
                }
                log_info!(target: "CoinJoin", "CoinJoinClientSession -- 1 - FINISHED - nDenomValue: {}, count: {}, nBalanceToDenominate: {}, {}",
                    denom.to_friendly_string(), count, balance_to_denominate.to_friendly_string(), tx_builder.to_string());
            }

            if finished {
                break;
            }
        }

        // Now that nCoinJoinDenomsGoal worth of each denom have been created or the max number of denoms given the value of the input, do something with the remainder.
        // if (txBuilder.CouldAddOutput(CCoinJoin::GetSmallestDenomination()) && nBalanceToDenominate >= CCoinJoin::GetSmallestDenomination() && txBuilder.CountOutputs() < COINJOIN_DENOM_OUTPUTS_THRESHOLD) {
        if tx_builder.could_add_output(CoinJoin::get_smallest_denomination()) && balance_to_denominate >= CoinJoin::get_smallest_denomination() && (tx_builder.outputs.len() as i32) < COINJOIN_DENOM_OUTPUTS_THRESHOLD {
            let largest_denom_value = denoms[0];
            log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - Process remainder: {}\n", tx_builder.to_string());

            let count_possible_outputs = |amount: u64, tx_builder: &TransactionBuilder| -> u64 {
                let mut vec_outputs: Vec<u64> = Vec::new();
                loop {
                    // Create a potential output
                    vec_outputs.push(amount);
                    if !tx_builder.could_add_outputs(&vec_outputs) || 
                        tx_builder.outputs.len() + vec_outputs.len() > COINJOIN_DENOM_OUTPUTS_THRESHOLD as usize {
                        // If it's not possible to add it due to insufficient amount left or total number of outputs exceeds
                        // COINJOIN_DENOM_OUTPUTS_THRESHOLD, drop the output again and stop trying.
                        vec_outputs.pop();
                        break;
                    }
                }
                vec_outputs.len() as u64
            };

            // Go big to small
            for denom_value in denoms {
                if balance_to_denominate <= 0 {
                    break;
                }
                
                let mut outputs = 0;
                // Number of denoms we can create given our denom and the amount of funds we have left
                let denoms_to_create_value = count_possible_outputs(*denom_value, &tx_builder);
                // Prefer overshooting the target balance by larger denoms (hence `+1`) instead of a more
                // accurate approximation by many smaller denoms. This is ok because when we get here we
                // should have nCoinJoinDenomsGoal of each smaller denom already. Also, without `+1`
                // we can end up in a situation when there is already nCoinJoinDenomsHardCap of smaller
                // denoms, yet we can't mix the remaining nBalanceToDenominate because it's smaller than
                // nDenomValue (and thus denomsToCreateBal == 0), so the target would never get reached
                // even when there is enough funds for that.
                let denoms_to_create_bal = (balance_to_denominate / *denom_value as u64) + 1;
                // Use the smaller value
                let denoms_to_create = denoms_to_create_value.min(denoms_to_create_bal);
                log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - nBalanceToDenominate: {}, nDenomValue: {}, denomsToCreateValue: {}, denomsToCreateBal: {}\n",
                    balance_to_denominate.to_friendly_string(), denom_value.to_friendly_string(), denoms_to_create_value.to_friendly_string(), denoms_to_create_bal.to_friendly_string());

                let mut it = map_denom_count[denom_value];

                for i in 0..denoms_to_create {
                    // Never go above the cap unless it's the largest denom
                    if *denom_value != largest_denom_value && it >= DEFAULT_COINJOIN_DENOMS_HARDCAP {
                        break;
                    }

                    // Increment helpers, add output and subtract denomination amount
                    if tx_builder.add_output(*denom_value) {
                        outputs += 1;
                        it += 1;
                        map_denom_count.insert(*denom_value, it);
                        balance_to_denominate = balance_to_denominate.saturating_sub(*denom_value);
                    } else {
                        log_error!(target: "CoinJoin", "CoinJoinClientSession -- 2 - Error: AddOutput failed at {}/{}, {}\n", i + 1, denoms_to_create, tx_builder.to_string());
                        break;
                    }

                    log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 2 - denomValue: {}, balanceToDenominate: {}, nOutputs: {}, {}\n",
                        denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                    
                    if (tx_builder.outputs.len() as i32) >= COINJOIN_DENOM_OUTPUTS_THRESHOLD {
                        break;
                    }
                }

                if (tx_builder.outputs.len() as i32) >= COINJOIN_DENOM_OUTPUTS_THRESHOLD {
                    break;
                }
            }
        }

        log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 3 - nBalanceToDenominate: {}, {}", balance_to_denominate.to_friendly_string(), tx_builder.to_string());

        for (denom, count) in &map_denom_count {
            log_debug!(target: "CoinJoin", "CoinJoinClientSession -- 3 - DONE - nDenomValue: {}, count: {}", denom.to_friendly_string(), count);
        }

        // No reasons to create mixing collaterals if we can't create denoms to mix
        if (create_mixing_collaterals && tx_builder.outputs.len() == 1) || tx_builder.outputs.len() == 0 {
            return false;
        }

        if !dry_run {
            let mut str_result = String::new();
            
            if !tx_builder.commit(&mut str_result, true, self.id) {
                log_error!(target: "CoinJoin", "CoinJoinClientSession -- 4 - Commit failed: {}\n", str_result);
                return false;
            }

            // use the same nCachedLastSuccessBlock as for DS mixing to prevent race
            client_manager.updated_success_block();
            log_info!(target: "CoinJoin", "CoinJoinClientSession -- 4: commited CreateDenomination tx, str_result: {}\n", str_result);
        }

        return true;
    }

    fn make_collateral_amounts(&mut self, client_manager: &mut CoinJoinClientManager) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }

        log_info!(target: "CoinJoin", "make_collateral_amounts");

        // NOTE: We do not allow txes larger than 100 kB, so we have to limit number of inputs here.
        // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
        // Knowing that each CTxIn is at least 148 B big, 400 inputs should take 400 x ~148 B = ~60 kB.
        // This still leaves more than enough room for another data of typical MakeCollateralAmounts tx.
        let mut vec_tally = self.mixing_wallet.borrow_mut().select_coins_grouped_by_addresses(false, false, true, 400);

        if vec_tally.is_empty() {
            log_warn!(target: "CoinJoin", "CoinJoinClientSession::MakeCollateralAmounts -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
            return false;
        }

        // Start from the smallest balances first to consume tiny amounts and cleanup UTXO a bit
        vec_tally.sort_by(|a, b| a.amount.cmp(&b.amount));

        // First try to use only non-denominated funds
        for item in &vec_tally {
            if !self.make_collateral_amounts_with_item(client_manager, item, false) {
                continue;
            }

            return true;
        }

        // There should be at least some denominated funds we should be able to break in pieces to continue mixing
        for item in &vec_tally {
            if !self.make_collateral_amounts_with_item(client_manager, item, true) {
                continue;
            }

            return true;
        }

        // If we got here then something is terribly broken actually
        log_error!(target: "CoinJoin", "CoinJoinClientSession::MakeCollateralAmounts -- ERROR: Can't make collaterals!");
        return false;
    }

    fn make_collateral_amounts_with_item(&mut self, client_manager: &mut CoinJoinClientManager, tally_item: &CompactTallyItem, try_denominated: bool) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }

        log_debug!(target: "CoinJoin", "make_collateral_amounts_with_item: {:?}", tally_item);

        // Denominated input is always a single one, so we can check its amount directly and return early
        if !try_denominated && tally_item.input_coins.len() == 1 && CoinJoin::is_denominated_amount(tally_item.amount) {
            return false;
        }

        // Skip single inputs that can be used as collaterals already
        if tally_item.input_coins.len() == 1 && CoinJoin::is_collateral_amount(tally_item.amount) {
            return false;
        }

        let mut tx_builder = TransactionBuilder::new(
            self.mixing_wallet.clone(),
            self.options.borrow().chain_type,
            tally_item.clone(),
            false
        );
        
        // Skip way too tiny amounts. Smallest we want is minimum collateral amount in a one output tx
        if !tx_builder.could_add_output(CoinJoin::get_collateral_amount()) {
            return false;
        }

        let case; // Just for debug logs

        if tx_builder.could_add_outputs(&[CoinJoin::get_max_collateral_amount(), CoinJoin::get_collateral_amount()]) {
            case = 1;
            // <case1>, see TransactionRecord::decomposeTransaction
            // Out1 == CoinJoin.GetMaxCollateralAmount()
            // Out2 >= CoinJoin.GetCollateralAmount()

            tx_builder.add_output(CoinJoin::get_max_collateral_amount());
            // Note, here we first add a zero amount output to get the remainder after all fees and then assign it
            if tx_builder.add_zero_output() {
                let amount_left = tx_builder.amount_left();
                // If remainder is denominated add one duff to the fee  
                if let Some(out) = tx_builder.outputs.last_mut() {
                    out.update_amount(
                        if CoinJoin::is_denominated_amount(amount_left) { amount_left - DUFFS } else { amount_left },
                        amount_left
                    );
                }
            }
        } else if tx_builder.could_add_outputs(&[CoinJoin::get_collateral_amount(), CoinJoin::get_collateral_amount()]) {
            case = 2;
            // <case2>, see TransactionRecord::decomposeTransaction
            // Out1 CoinJoin.isCollateralAmount()
            // Out2 CoinJoin.isCollateralAmount()

            // First add two outputs to get the available value after all fees
            tx_builder.add_zero_output();
            tx_builder.add_zero_output();

            // Create two equal outputs from the available value. This adds one duff to the fee if txBuilder.GetAmountLeft() is odd.
            let amount_outputs = tx_builder.amount_left() / 2;

            assert!(CoinJoin::is_collateral_amount(amount_outputs));

            let amount_left = tx_builder.amount_left();
            let last_index = tx_builder.outputs.len() - 1;

            if let Some(out1) = tx_builder.outputs.get_mut(last_index) {
                out1.update_amount(amount_outputs, amount_left);
            }

            if let Some(out2) = tx_builder.outputs.get_mut(last_index - 1) {
                out2.update_amount(amount_outputs, amount_left);
            }
        } else { // still at least possible to add one CoinJoin.GetCollateralAmount() output
            case = 3;
            // <case3>, see TransactionRecord::decomposeTransaction
            // Out1 CoinJoin.isCollateralAmount()
            // Out2 Skipped

            tx_builder.add_zero_output();
            let amount_left = tx_builder.amount_left();

            if let Some(out) = tx_builder.outputs.last_mut() {
                out.update_amount(amount_left, amount_left);
                assert!(CoinJoin::is_collateral_amount(out.amount));
            }
        }

        log_info!(target: "CoinJoin", "Done with case {}: {}", case, tx_builder);
        assert!(TransactionBuilder::is_dust(tx_builder.amount_left()));

        let mut str_result = String::new();

        if !tx_builder.commit(&mut str_result, false, self.id) {
            log_error!(target: "CoinJoin", "Commit failed: {}", str_result);
            return false;
        }

        client_manager.updated_success_block();
        log_info!(target: "CoinJoin", "commited MakeCollateralInputs tx, str_result: {}", str_result);

        return true;
    }


    pub fn set_status(&mut self, pool_status: PoolStatus) {
        self.str_auto_denom_result = CoinJoin::get_status_message(pool_status).to_string();

        if pool_status.is_error() {
            log_error!(target: "CoinJoin", "Session has an error: {}", self.str_auto_denom_result);
        } else if pool_status.is_warning() {
            log_warn!(target: "CoinJoin", "Session has a warning: {}", self.str_auto_denom_result);
        }

        self.base_session.status = pool_status;
    
        if pool_status.should_stop() {
            log_info!(target: "CoinJoin", "Session has nothing to do: {:?}", pool_status);
            self.has_nothing_to_do = true;
        }
    }

    pub fn check_timeout(&mut self) -> bool {
        match self.base_session.state {
            PoolState::Idle => return false,
            PoolState::Error => {
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if self.base_session.time_last_successful_step + 10 >= current_time {
                    // reset after being in POOL_STATE_ERROR for 10 or more seconds
                    self.set_null();
                }
                return false;
            },
            _ => {}
        }

        let lag_time = 10; // give the server a few extra seconds before resetting.
        let timeout = match self.base_session.state {
            PoolState::Signing => COINJOIN_SIGNING_TIMEOUT,
            _ => COINJOIN_QUEUE_TIMEOUT,
        };
        
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let is_timeout = current_time >= self.base_session.time_last_successful_step + timeout + lag_time;

        if !is_timeout {
            return false;
        }

        log_warn!(target: "CoinJoin", "connect: {} {} timed out ({})",
                 if self.base_session.state == PoolState::Signing { "Signing at session" } else { "Session" },
                 self.id, timeout);

        self.queue_session_lifecycle_listeners(true, self.base_session.state, PoolMessage::ErrTimeout);
        self.base_session.state = PoolState::Error;
        self.set_status(PoolStatus::Timeout);
        self.unlock_coins();
        self.key_holder_storage.return_all();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.base_session.time_last_successful_step = current_time;
        self.str_last_message = CoinJoin::get_message_by_id(PoolMessage::ErrSession).to_string();

        return true;
    }

    pub fn is_mixing_fee_tx(&self, tx_id: UInt256) -> bool {
        return self.collateral_session_map.contains_key(&tx_id);
    }

    fn unlock_coins(&mut self) {
        if !self.options.borrow().enable_coinjoin {
            return;
        }

        // TODO (DashJ): should we wait here? check Dash Core code

        for outpoint in &self.outpoint_locked {
            self.mixing_wallet.borrow_mut().unlock_coin(outpoint);
        }

        self.outpoint_locked.clear();
    }

    fn set_null(&mut self) {
        if let Some(dmn) = self.mixing_masternode.clone() {
            if self.mixing_wallet.borrow().is_masternode_or_disconnect_requested(dmn.socket_address) {
                if !self.mixing_wallet.borrow().disconnect_masternode(dmn.socket_address) {
                    log_info!(target: "CoinJoin", "not closing existing masternode: {}", dmn.socket_address);
                }
            } else {
                log_info!(target: "CoinJoin", "not closing masternode since it is not found: {}", dmn.socket_address);
            }
        }

        self.mixing_masternode = None;
        self.pending_dsa_request = None;
        self.base_session.set_null();
    }

    fn create_collateral_transaction(&mut self, str_reason: &mut String) -> bool {
        let mut coin_control = CoinControl::new();
        coin_control.coin_type = CoinType::OnlyCoinJoinCollateral;
        let coins = self.mixing_wallet.borrow_mut().available_coins(true, coin_control);

        if coins.is_empty() {
            str_reason.push_str("CoinJoin requires a collateral transaction and could not locate an acceptable input!");
            return false;
        }

        let mut rng = rand::thread_rng();
        let txout = &coins[rng.gen_range(0..coins.len())];
        let inputs = vec![TransactionInput {
            input_hash: txout.tx_outpoint.hash,
            index: txout.tx_outpoint.index,
            script: None,
            signature: Some(Vec::new()),
            sequence: TXIN_SEQUENCE
        }];
        let mut tx_collateral = Transaction {
            inputs: inputs,
            outputs: Vec::new(),
            lock_time: 0,
            version: 1,
            tx_hash: None,
            tx_type: TransactionType::Classic,
            payload_offset: 0,
            block_height: TX_UNCONFIRMED as u32
        };

        // pay collateral charge in fees
        // NOTE: no need for protobump patch here,
        // CCoinJoin::IsCollateralAmount in GetCollateralTxDSIn should already take care of this
        if txout.output.amount >= CoinJoin::get_collateral_amount() * 2 {
            // make our change address
            let mut reserve_destination = ReserveDestination::new(self.mixing_wallet.clone());
            
            if let Some(dest) = reserve_destination.get_reserved_destination(true) {
                reserve_destination.keep_destination();
                // return change
                tx_collateral.outputs.push(
                    TransactionOutput {
                        amount: txout.output.amount.saturating_sub(CoinJoin::get_collateral_amount()),
                        script: Some(dest),
                        address: None
                    }
                );
            }
        } else { // txout.nValue < CCoinJoin::GetCollateralAmount() * 2
            // create dummy data output only and pay everything as a fee
            tx_collateral.outputs.push(
                TransactionOutput {
                    amount: 0,
                    script: Some(vec![OP_RETURN.into_u8()]),
                    address: None
                }
            );
        }

        log_info!(target: "CoinJoin", "sign collateral");
        log_debug!(target: "CoinJoin", "tx_collateral={:?}", tx_collateral);
        if let Some(signed_tx) = self.mixing_wallet.borrow().sign_transaction(&tx_collateral, false) {
            if let Some(tx_id) = signed_tx.tx_hash {
                self.tx_my_collateral = Some(signed_tx);
                self.is_my_collateral_valid = true;

                if !self.collateral_session_map.contains_key(&tx_id) {
                    self.collateral_session_map.insert(tx_id, 0);
                }
            }

            return true;
        }

        log_warn!(target: "CoinJoin", "Unable to sign collateral transaction!");
        str_reason.push_str("Unable to sign collateral transaction!");

        return false;
    }

    fn join_existing_queue(&mut self, client_manager: &mut CoinJoinClientManager, balance_needs_anonymized: u64) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }

        let mn_list = client_manager.get_mn_list();// TODO: at_chain_tip ?
        let queue_manager_rc = self.queue_manager.clone();
        let mut queue_manager = queue_manager_rc.borrow_mut();
        let mut dsq_option = queue_manager.get_queue_item_and_try();

        while let Some(dsq) = dsq_option.clone() {
            let dmn = mn_list.masternode_for(dsq.pro_tx_hash.reversed());

            match (dmn, self.tx_my_collateral.clone()) {
                (None, _) => {
                    log_info!(target: "CoinJoin", "masternode is not in masternode list, masternode={}", dsq.pro_tx_hash);
                    dsq_option = queue_manager.get_queue_item_and_try();
                    continue;
                },
                (Some(dmn), Some(tx)) => {
                    log_debug!(target: "CoinJoin", "trying existing queue: {}", dsq);
                    let mut vec_tx_dsin_tmp = Vec::new();

                    if !self.mixing_wallet.borrow_mut().select_tx_dsins_by_denomination(dsq.denomination, balance_needs_anonymized, &mut vec_tx_dsin_tmp) {
                        log_debug!(target: "CoinJoin", "couldn't match denomination {} ({})", dsq.denomination, CoinJoin::denomination_to_string(dsq.denomination));
                        dsq_option = queue_manager.get_queue_item_and_try();
                        continue;
                    }

                    client_manager.add_used_masternode(dsq.pro_tx_hash);

                    if self.mixing_wallet.borrow().is_masternode_or_disconnect_requested(dmn.socket_address) {
                        log_debug!(target: "CoinJoin", "skipping masternode connection, addr={}", dmn.socket_address);
                        dsq_option = queue_manager.get_queue_item_and_try();
                        continue;
                    }

                    self.base_session.session_denom = dsq.denomination;
                    self.mixing_masternode = Some(dmn.clone());
                    self.pending_dsa_request = Some(PendingDsaRequest::new(
                        dmn.socket_address,
                        CoinJoinAcceptMessage::new(
                                self.base_session.session_denom,
                                tx
                            )
                    ));
                    self.mixing_wallet.borrow_mut().add_pending_masternode(dmn.provider_registration_transaction_hash, self.id);
                    self.base_session.state = PoolState::Queue;
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    self.base_session.time_last_successful_step = current_time;
                    log_info!(target: "CoinJoin", "join existing queue -> pending connection, sessionDenom: {} ({}), addr={}",
                             self.base_session.session_denom, CoinJoin::denomination_to_string(self.base_session.session_denom), dmn.socket_address);
                    self.set_status(PoolStatus::Connecting);
                    self.joined = true;
                    return true;
                }
                (Some(_), None) => {
                    log_warn!(target: "CoinJoin", "tx_collateral is missing");
                }
            }
        }

        self.set_status(PoolStatus::WarnNoMixingQueues);
        return false;
    }

    fn start_new_queue(&mut self, client_manager: &mut CoinJoinClientManager, balance_needs_anonymized: u64) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }
        if balance_needs_anonymized <= 0 {
            return false;
        }

        let mut tries = 0;
        let mn_list = client_manager.get_mn_list();
        let mn_count = mn_list.masternodes.values().filter(|x| x.is_valid).count();
        let mut set_amounts = HashSet::new();

        if !self.mixing_wallet.borrow_mut().select_denominated_amounts(balance_needs_anonymized, &mut set_amounts) {
            if !self.last_create_denominated_result {
                self.set_status(PoolStatus::ErrNoInputs);
            }
            return false;
        }

        while tries < 10 {
            let dmn = client_manager.get_random_not_used_masternode();

            match dmn {
                None => {
                    self.set_status(PoolStatus::ErrMasternodeNotFound);
                    return false;
                },
                Some(dmn) => {
                    client_manager.add_used_masternode(dmn.provider_registration_transaction_hash);
                    
                    {
                        let metadata_manager = &mut self.queue_manager.borrow_mut().masternode_metadata_manager;
                        let last_dsq = metadata_manager.get_meta_info(dmn.provider_registration_transaction_hash, true).unwrap().last_dsq;
                        let dsq_threshold = metadata_manager.get_dsq_threshold(dmn.provider_registration_transaction_hash, mn_count as u64);
                        
                        if last_dsq != 0 && dsq_threshold > metadata_manager.dsq_count {
                            log_warn!(target: "CoinJoin", "warning: Too early to mix on this masternode! masternode={} addr={} nLastDsq={} nDsqThreshold={} nDsqCount={}",
                                    dmn.provider_registration_transaction_hash, dmn.socket_address, last_dsq, dsq_threshold, metadata_manager.dsq_count);
                            tries += 1;
                            continue;
                        }

                        if self.mixing_wallet.borrow_mut().is_masternode_or_disconnect_requested(dmn.socket_address) {
                            log_warn!(target: "CoinJoin", "warning: skipping masternode connection, addr={}", dmn.socket_address);
                            tries += 1;
                            continue;
                        }
                    }

                    log_info!(target: "CoinJoin", "attempt {} connection to masternode {}, protx: {}", tries + 1, dmn.socket_address, dmn.provider_registration_transaction_hash);

                    while self.base_session.session_denom == 0 {
                        for amount in &set_amounts {
                            if set_amounts.len() > 1 && rand::random::<bool>() {
                                continue;
                            }
                            self.base_session.session_denom = CoinJoin::amount_to_denomination(*amount);
                            break;
                        }
                    }

                    self.mixing_masternode = Some(dmn.clone());
                    self.mixing_wallet.borrow_mut().add_pending_masternode(dmn.provider_registration_transaction_hash, self.id);
                    self.pending_dsa_request = Some(PendingDsaRequest::new(
                        dmn.socket_address,
                        CoinJoinAcceptMessage::new(
                            self.base_session.session_denom,
                            self.tx_my_collateral.clone().unwrap()
                        )
                    ));
                    self.base_session.state = PoolState::Queue;
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    self.base_session.time_last_successful_step = current_time;
                    log_info!(target: "CoinJoin", "start new queue -> pending connection, sessionDenom: {} ({}), addr={}",
                            self.base_session.session_denom, CoinJoin::denomination_to_string(self.base_session.session_denom), dmn.socket_address);
                    self.mixing_wallet.borrow_mut().start_manager_async();
                    self.set_status(PoolStatus::Connecting);
                    self.joined = false;
                    
                    return true;
                }
            }
        }
        self.str_auto_denom_result = "Failed to start a new mixing queue".to_string();
        return false;
    }

    /// As a client, submit part of a future mixing transaction to a Masternode to start the process
    pub fn submit_denominate(&mut self) -> bool {
        let mut str_error = String::new();
        let mut vec_tx_dsin = Vec::new();
        let mut vec_psin_out_pairs_tmp = Vec::new();

        if !self.select_denominate(&mut str_error, &mut vec_tx_dsin) {
            log_error!(target: "CoinJoin", "SelectDenominate failed, error: {}", str_error);
            return false;
        }

        let mut vec_inputs_by_rounds = Vec::new();
        let rounds = self.options.borrow().coinjoin_rounds;
        let coinjoin_rounds = self.options.borrow().coinjoin_rounds;
        let random_rounds = self.options.borrow().coinjoin_random_rounds;

        for i in 0..(rounds + random_rounds) {
            if self.prepare_denominate(i, i, &mut str_error, &vec_tx_dsin, &mut vec_psin_out_pairs_tmp, true) {
                log_debug!(target: "CoinJoin", "Running CoinJoin denominate for {} rounds, success", i);
                vec_inputs_by_rounds.push((i, vec_psin_out_pairs_tmp.len()));
            }
        }

        // more inputs first, for equal input count prefer the one with fewer rounds
        vec_inputs_by_rounds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let rounds = vec_inputs_by_rounds[0].0;

        if self.prepare_denominate(rounds, rounds, &mut str_error, &vec_tx_dsin, &mut vec_psin_out_pairs_tmp, false) {
            log_debug!(target: "CoinJoin", "Running CoinJoin denominate for {} rounds, success", rounds);
            return self.send_denominate(vec_psin_out_pairs_tmp);
        }

        // We failed? That's strange but let's just make final attempt and try to mix everything
        if self.prepare_denominate(0, coinjoin_rounds - 1, &mut str_error, &vec_tx_dsin, &mut vec_psin_out_pairs_tmp, false) {
            log_debug!(target: "CoinJoin", "Running CoinJoin denominate for all rounds, success");
            return self.send_denominate(vec_psin_out_pairs_tmp);
        }

        // Should never actually get here but just in case
        log_debug!(target: "CoinJoin", "Running CoinJoin denominate for all rounds, error: {}", str_error);
        self.str_auto_denom_result = str_error;
        
        return false;
    }

    /// step 0: select denominated inputs and txouts
    fn select_denominate(&mut self, str_error_ret: &mut String, vec_tx_dsin_ret: &mut Vec<CoinJoinTransactionInput>) -> bool {
        if !self.options.borrow().enable_coinjoin {
            return false;
        }

        // if sm_wallet.IsLocked(true) { TODO: recheck
        //     str_error_ret.push_str("Wallet locked, unable to create transaction!");
        //     return false;
        // }

        if self.base_session.entries.len() > 0 {
            str_error_ret.push_str("Already have pending entries in the CoinJoin pool ");
            return false;
        }

        vec_tx_dsin_ret.clear();
        let selected = self.mixing_wallet.borrow_mut().select_tx_dsins_by_denomination(
            self.base_session.session_denom, 
            CoinJoin::max_pool_amount(), 
            vec_tx_dsin_ret
        );

        if !selected {
            str_error_ret.push_str(
                &format!("Can't select current denominated inputs: {} for session {} ",
                    CoinJoin::denomination_to_amount(self.base_session.session_denom).to_friendly_string(), self.base_session.session_id)
            );
            
            for input in vec_tx_dsin_ret.iter() {
                str_error_ret.push_str(&format!("\n{:?} ", input));
            }

            return false;
        }

        return true;
    }

    /// step 1: prepare denominated inputs and outputs
    fn prepare_denominate(
        &mut self, 
        min_rounds: i32, 
        max_rounds: i32, 
        str_error_ret: &mut String,
        vec_tx_dsin: &Vec<CoinJoinTransactionInput>, 
        vec_psin_out_pairs_ret: &mut Vec<(CoinJoinTransactionInput, TransactionOutput)>, 
        dry_run: bool
    ) -> bool {
        if !CoinJoin::is_valid_denomination(self.base_session.session_denom) {
            str_error_ret.push_str("Incorrect session denom");
            return false;
        }
        let denom_amount = CoinJoin::denomination_to_amount(self.base_session.session_denom);

        let mut steps = 0;
        vec_psin_out_pairs_ret.clear();

        for entry in vec_tx_dsin.iter() {
            if steps >= COINJOIN_ENTRY_MAX_SIZE {
                break;
            }

            if entry.rounds < min_rounds || entry.rounds > max_rounds {
                continue;
            }

            let script_denom;
            if dry_run {
                script_denom = Some(vec![]);
            } else {
                // randomly skip some inputs when we have at least one of the same denom already
                if steps >= 1 && rand::thread_rng().gen_range(0..5) == 0 {
                    steps += 1;
                    continue;
                }

                script_denom = self.key_holder_storage.add_key(self.mixing_wallet.clone());
            }
            vec_psin_out_pairs_ret.push((entry.clone(), TransactionOutput { amount: denom_amount as u64, script: script_denom, address: None } ));
            steps += 1;
        }

        if vec_psin_out_pairs_ret.is_empty() {
            self.key_holder_storage.return_all();
            str_error_ret.push_str("Can't prepare current denominated outputs");
            return false;
        }

        if !dry_run {
            for pair in vec_psin_out_pairs_ret.iter() {
                self.mixing_wallet.borrow_mut().lock_coin(pair.0.outpoint());
                self.outpoint_locked.push(pair.0.outpoint());
            }
        }

        true
    }

    /// step 2: send denominated inputs and outputs prepared in step 1
    fn send_denominate(&mut self, vec_psin_out_pairs: Vec<(CoinJoinTransactionInput, TransactionOutput)>) -> bool {
        if self.tx_my_collateral.is_none() || self.tx_my_collateral.as_ref().unwrap().inputs.is_empty() {
            log_warn!(target: "CoinJoin", "CoinJoin collateral not set");
            return false;
        }

        // we should already be connected to a Masternode
        if self.base_session.session_id == 0 {
            log_warn!(target: "CoinJoin", " No Masternode has been selected yet.");
            self.unlock_coins();
            self.key_holder_storage.return_all();
            self.set_null();

            return false;
        }

        self.base_session.state = PoolState::AcceptingEntries;
        self.str_auto_denom_result = String::new();

        let mut tx = Transaction {  // for debug purposes only
            inputs: vec![],
            outputs: vec![],
            lock_time: 0,
            version: 0,
            tx_hash: None,
            tx_type: TransactionType::Classic,
            payload_offset: 0,
            block_height: 0,
        };
        let mut vec_tx_dsin_tmp = Vec::new();
        let mut vec_tx_out_tmp = Vec::new();

        for pair in vec_psin_out_pairs {
            vec_tx_dsin_tmp.push(pair.0.txin.clone());
            vec_tx_out_tmp.push(pair.1.clone());
            tx.inputs.push(pair.0.txin);
            tx.outputs.push(pair.1);
        }

        log_info!(target: "CoinJoin", "Submitting partial tx to session {}", self.base_session.session_id);
        log_debug!(target: "CoinJoin", "tx={:?}", tx);

        // Store our entry for later use
        let entry = CoinJoinEntry {
            mixing_inputs: vec_tx_dsin_tmp, 
            mixing_outputs: vec_tx_out_tmp, 
            tx_collateral: self.tx_my_collateral.as_ref().unwrap().clone() 
        };
        self.base_session.entries.push(entry.clone());
        self.relay(&entry);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.base_session.time_last_successful_step = current_time;

        return true;
    }

    fn relay(&self, entry: &CoinJoinEntry) {
        if let Some(mn) = self.mixing_masternode.as_ref() {
            let mut buffer = vec![];
            entry.consensus_encode(&mut buffer).unwrap();

            if !self.mixing_wallet.borrow_mut().send_message(buffer, entry.get_message_type(), &mn.socket_address, true) {
                log_info!(target: "CoinJoin", "failed to send dsi to {}", mn.socket_address);
            }
        }
    }

    pub fn process_message(&mut self, peer: &SocketAddress, message: &CoinJoinMessage) -> bool {
        match message {
            CoinJoinMessage::StatusUpdate(status_update) => {
                self.process_status_update(peer, status_update);
                return false;
            },
            CoinJoinMessage::FinalTransaction(final_tx) => {
                self.process_final_transaction(peer, final_tx);
                return false;
            },
            CoinJoinMessage::Complete(complete) => {
                return self.process_complete(peer, complete);
            },
            _ => { return false }
        }
    }

    pub fn reset_pool(&mut self) {
        self.tx_my_collateral = None;
        self.unlock_coins();
        self.key_holder_storage.return_all();
        self.set_null();
    }

    fn process_status_update(&mut self, peer: &SocketAddress, status_update: &CoinJoinStatusUpdate) {
        if self.mixing_masternode.is_none() {
            return;
        }

        if self.mixing_masternode.as_ref().unwrap().socket_address != *peer {
            return;
        }

        self.process_pool_state_update(peer, status_update);
    }

    /// Process Masternode updates about the progress of mixing
    fn process_pool_state_update(&mut self, peer: &SocketAddress, status_update: &CoinJoinStatusUpdate) {
        log_debug!(target: "CoinJoin", "status update received: {:?} from {}", status_update, peer);

        // do not update state when mixing client state is one of these
        if self.base_session.state == PoolState::Idle || self.base_session.state == PoolState::Error {
            return;
        }
        
        if status_update.pool_state < PoolState::pool_state_min() || status_update.pool_state > PoolState::pool_state_max() {
            return;
        }

        if status_update.message_id < PoolMessage::msg_pool_min() || status_update.message_id > PoolMessage::msg_pool_max() {
            return;
        }

        let mut str_message_tmp = CoinJoin::get_message_by_id(status_update.message_id).to_string();
        self.str_auto_denom_result = format!("Masternode: {}", str_message_tmp);

        match status_update.status_update {
            PoolStatusUpdate::Rejected => {
                log_info!(target: "CoinJoin", "session: rejected by Masternode {}: {}", peer, str_message_tmp);
                self.base_session.state = PoolState::Error;
                self.unlock_coins();
                self.key_holder_storage.return_all();

                match status_update.message_id {
                    PoolMessage::ErrInvalidCollateral => {
                        if let Some(collateral) = &self.tx_my_collateral {
                            log_warn!(target: "CoinJoin", "collateral invalid: {}", self.coinjoin.borrow().is_collateral_valid(collateral, true));
                        } else {
                            log_warn!(target: "CoinJoin", "collateral invalid, tx_my_collateral is None");
                        }

                        self.is_my_collateral_valid = false;
                        self.set_null(); // for now lets disconnect.  TODO(DashJ): Why is the collateral invalid?
                    },
                    _ => {
                        log_warn!(target: "CoinJoin", "rejected for other reasons");
                    }
                }
                let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                self.base_session.time_last_successful_step = current_time;
                self.str_last_message = str_message_tmp;
            },
            PoolStatusUpdate::Accepted => {
                if let Some(collateral) = &self.tx_my_collateral {
                    if self.base_session.state == status_update.pool_state && 
                        status_update.pool_state == PoolState::Queue && 
                        self.base_session.session_id == 0 &&
                        status_update.session_id != 0
                    {
                        // new session id should be set only in POOL_STATE_QUEUE state
                        self.base_session.session_id = status_update.session_id;
                        self.collateral_session_map.insert(collateral.tx_hash.unwrap(), status_update.session_id);
                        self.base_session.time_last_successful_step = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                        str_message_tmp = format!("{} Set SID to {}", str_message_tmp, status_update.session_id);
                        self.queue_session_lifecycle_listeners(false, self.base_session.state, PoolMessage::MsgSuccess);
                    }

                    log_debug!(target: "CoinJoin", "session: accepted by Masternode: {}", str_message_tmp);
                } else {
                    log_warn!(target: "CoinJoin", "collateral accepted but tx_my_collateral is None");
                }
            }
        }
    }

    fn process_complete(& mut self, peer: &SocketAddress, complete_message: &CoinJoinCompleteMessage) -> bool {
        if self.mixing_masternode.is_none() {
            return false;
        }

        if self.mixing_masternode.as_ref().unwrap().socket_address != *peer {
            return false;
        }

        if complete_message.msg_message_id < PoolMessage::msg_pool_min() || complete_message.msg_message_id > PoolMessage::msg_pool_max() {
            log_warn!(target: "CoinJoin", "msgID is out of bounds: {:?}", complete_message.msg_message_id);
            return false;
        }

        if self.base_session.session_id != complete_message.msg_session_id {
            log_warn!(target: "CoinJoin", "message doesn't match current CoinJoin session: SID: {}  msgID: {}  ({})",
                    self.base_session.session_id, complete_message.msg_session_id, CoinJoin::get_message_by_id(complete_message.msg_message_id));
            return false;
        }

        log_info!(target: "CoinJoin", "msgSID {}  msg {:?} ({})", complete_message.msg_session_id,
                 complete_message.msg_message_id, CoinJoin::get_message_by_id(complete_message.msg_message_id));

        return self.completed_transaction(complete_message.msg_message_id);
    }

    fn completed_transaction(&mut self, message_id: PoolMessage) -> bool {
        let mut update_success_block = false;

        if message_id == PoolMessage::MsgSuccess {
            log_info!(target: "CoinJoin", "completedTransaction -- success");
            self.queue_session_lifecycle_listeners(true, self.base_session.state, PoolMessage::MsgSuccess);
            self.key_holder_storage.keep_all();
            update_success_block = true;
        } else {
            log_error!(target: "CoinJoin", "completedTransaction -- error");
            self.key_holder_storage.return_all();
        }

        self.unlock_coins();
        self.set_null();
        self.set_status(PoolStatus::Complete);
        self.str_last_message = CoinJoin::get_message_by_id(message_id).to_string();

        return update_success_block;
    }

    fn process_final_transaction(&mut self, peer: &SocketAddress, final_tx: &CoinJoinFinalTransaction) {
        if self.mixing_masternode.is_none() {
            return;
        }

        if self.mixing_masternode.as_ref().unwrap().socket_address != *peer {
            return;
        }

        if self.base_session.session_id != final_tx.msg_session_id {
            log_warn!(target: "CoinJoin", "DSFINALTX: message doesn't match current CoinJoin session: sessionID: {}  msgSessionID: {}",
                    self.base_session.session_id, final_tx.msg_session_id);
            return;
        }

        log_debug!(target: "CoinJoin", "DSFINALTX: txNew {:?}", final_tx.tx);

        // check to see if input is spent already? (and probably not confirmed)
        self.sign_final_transaction(&final_tx.tx, peer);
    }

    /// As a client, check and sign the final transaction
    fn sign_final_transaction(&mut self, final_transaction_new: &Transaction, peer: &SocketAddress) {
        if !self.options.borrow().enable_coinjoin {
            return;
        }

        if self.mixing_masternode.is_none() {
            return;
        }

        let mut final_mutable_transaction = final_transaction_new.clone();
        
        // STEP 1: check final transaction general rules

        // Make sure it's BIP69 compliant
        final_mutable_transaction.inputs.sort_by(Self::compare_input_bip69);
        final_mutable_transaction.outputs.sort_by(Self::compare_output_bip69);

        if UInt256::sha256d(final_mutable_transaction.to_data()) != UInt256::sha256d(final_transaction_new.to_data()) {
            log_error!(target: "CoinJoin", "Masternode {} is not BIP69 compliant!", self.mixing_masternode.as_ref().unwrap().provider_registration_transaction_hash);
            self.unlock_coins();
            self.key_holder_storage.return_all();
            self.set_null();
            return;
        }

        // Make sure all inputs/outputs are valid
        let is_valid_ins_outs = self.base_session.is_valid_in_outs(&final_mutable_transaction.inputs, &final_mutable_transaction.outputs);

        if !is_valid_ins_outs.result {
            log_error!(target: "CoinJoin", "IsValidInOuts() failed: {}", CoinJoin::get_message_by_id(is_valid_ins_outs.message_id));
            self.unlock_coins();
            self.key_holder_storage.return_all();
            self.set_null();
            return;
        }

        // STEP 2: make sure our own inputs/outputs are present, otherwise refuse to sign
        let mut coins = vec![];

        for entry in &self.base_session.entries {
            // Check that the final transaction has all our outputs
            for txout in &entry.mixing_outputs {
                let found = final_mutable_transaction.outputs.iter().any(|txout_final| 
                    txout_final.amount == txout.amount && txout_final.script == txout.script
                );
                
                if !found {
                    // Something went wrong and we'll refuse to sign. It's possible we'll be charged collateral. But that's
                    // better than signing if the transaction doesn't look like what we wanted.
                    log_warn!(target: "CoinJoin", "an output is missing, refusing to sign!");
                    log_debug!(target: "CoinJoin", "txout={:?}", txout);
                    self.unlock_coins();
                    self.key_holder_storage.return_all();
                    self.set_null();
                    return;
                }
            }
        
            for txin in &entry.mixing_inputs {
                /* Sign my transaction and all outputs */
                let mut my_input_index: Option<usize> = None;

                for (i, txin_final) in final_mutable_transaction.inputs.iter().enumerate() {
                    if txin_final.input_hash == txin.input_hash && txin_final.index == txin.index {
                        my_input_index = Some(i);
                        break;
                    }
                }

                if let Some(index) = my_input_index {
                    let input = final_mutable_transaction.inputs[index].clone();
                    // add a pair with an empty value
                    coins.push(input);
                } else {
                    // Can't find one of my own inputs, refuse to sign. It's possible we'll be charged collateral. But that's
                    // better than signing if the transaction doesn't look like what we wanted.
                    log_warn!(target: "CoinJoin", "missing input!");
                    log_debug!(target: "CoinJoin", "txdsin={:?}", txin);
                    self.unlock_coins();
                    self.key_holder_storage.return_all();
                    self.set_null();
                    return;
                }
            }
        }

        let signed_tx = self.mixing_wallet.borrow_mut().sign_transaction(&final_mutable_transaction, true);

        if let Some(tx) = signed_tx {
            let mut signed_inputs = vec![];
            
            for txin in &tx.inputs {
                if coins.iter().any(|coin| coin.input_hash == txin.input_hash && coin.index == txin.index) {
                    signed_inputs.push(txin.clone());
                }
            }

            if signed_inputs.is_empty() {
                log_warn!(target: "CoinJoin", "can't sign anything!");
                self.unlock_coins();
                self.key_holder_storage.return_all();
                self.set_null();
                return;
            }

            // push all of our signatures to the Masternode
            let message = CoinJoinSignedInputs { inputs: signed_inputs };
            log_info!(target: "CoinJoin", "pushing signed inputs to the masternode");
            log_debug!(target: "CoinJoin", "{}", message);
            let mut buffer = vec![];
            message.consensus_encode(&mut buffer).unwrap();
            self.mixing_wallet.borrow_mut().send_message(buffer, message.get_message_type(), peer, true);
            self.base_session.state = PoolState::Signing;
            self.base_session.time_last_successful_step = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        } else {
            log_warn!(target: "CoinJoin", "sign_transaction returned false for the tx");
        }
    }

    fn compare_input_bip69(a: &TransactionInput, b: &TransactionInput) -> Ordering {
        if a.input_hash == b.input_hash {
            return a.index.cmp(&b.index);
        }
    
        let rev_hash_a: Vec<u8> = a.input_hash.reversed().0.to_vec();
        let rev_hash_b: Vec<u8> = b.input_hash.reversed().0.to_vec();
        
        rev_hash_a.cmp(&rev_hash_b)
    }
    
    fn compare_output_bip69(a: &TransactionOutput, b: &TransactionOutput) -> Ordering {
        match a.amount.cmp(&b.amount) {
            Ordering::Equal => a.script.cmp(&b.script),
            other => other,
        }
    }

    fn queue_session_lifecycle_listeners(&self, is_complete: bool, state: PoolState, pool_message: PoolMessage) {
        unsafe {
            let boxed_session_id = boxed(self.id.0);
            let boxed_mixing_mn_ip = if let Some(mn) = self.mixing_masternode.as_ref() {
                boxed(mn.socket_address.ip_address.0)
            } else {
                boxed(UInt128::ip_address_from_u32(0).0)
            };

            (self.session_lifecycle_listener)(
                is_complete,
                self.base_session.session_id,
                boxed_session_id,
                self.base_session.session_denom,
                state,
                pool_message,
                boxed_mixing_mn_ip,
                self.joined,
                self.context
            );

            unbox_any(boxed_session_id);
            unbox_any(boxed_mixing_mn_ip);
        }
    }
}
