use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use dash_spv_masternode_processor::blockdata::opcodes::all::OP_RETURN;
use dash_spv_masternode_processor::chain::params::DUFFS;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::models::MasternodeEntry;
use dash_spv_masternode_processor::secp256k1::rand::{self, Rng};
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use dash_spv_masternode_processor::util::script::ScriptType;

use crate::coinjoin::CoinJoin;
use crate::constants::{COINJOIN_DENOM_OUTPUTS_THRESHOLD, DEFAULT_COINJOIN_DENOMS_GOAL, DEFAULT_COINJOIN_DENOMS_HARDCAP};
use crate::ffi::callbacks::{AvailableCoins, CommitTransaction, DestroyGatheredOutputs, DestroySelectedCoins, DestroyWalletTransaction, FreshCoinJoinAddress, GetWalletTransaction, InputsWithAmount, IsMineInput, SelectCoinsGroupedByAddresses, SignTransaction};
use crate::models::coin_control::{CoinControl, CoinType};
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

static mut NEXT_ID: i32 = 0;

pub struct CoinJoinClientSession {
    id: i32,
    coinjoin: CoinJoin,
    mixing_wallet: Rc<RefCell<WalletEx>>,
    base_session: CoinJoinBaseSession,
    options: CoinJoinClientOptions,
    key_holder_storage: KeyHolderStorage,
    state: PoolState,
    status: PoolStatus,
    last_create_denominated_result: bool,
    session_id: i32,
    outpoint_locked: Vec<TxOutPoint>,
    mixing_masternode: Option<MasternodeEntry>,
    pending_dsa_request: Option<PendingDsaRequest>,
    tx_my_collateral: Option<Transaction>,
    is_my_collateral_valid: bool,
    collateral_session_map: HashMap<UInt256, i32>,
    str_auto_denom_result: String
}

impl CoinJoinClientSession {
    pub fn new(
        coinjoin: CoinJoin,
        options: CoinJoinClientOptions,
        sign_transaction: SignTransaction,
        get_wallet_transaction: GetWalletTransaction,
        destroy_transaction: DestroyWalletTransaction,
        is_mine: IsMineInput,
        available_coins: AvailableCoins,
        destroy_gathered_outputs: DestroyGatheredOutputs,
        selected_coins: SelectCoinsGroupedByAddresses,
        destroy_selected_coins: DestroySelectedCoins,
        inputs_with_amount: InputsWithAmount,
        fresh_coinjoin_key: FreshCoinJoinAddress,
        commit_transaction: CommitTransaction,
        context: *const std::ffi::c_void
    ) -> Self {
        unsafe { NEXT_ID += 1; } // TODO

        let wallet_ex = Rc::new(RefCell::new(WalletEx::new(
            context, 
            options.clone(), 
            get_wallet_transaction, 
            sign_transaction,
            destroy_transaction, 
            is_mine, 
            available_coins, 
            destroy_gathered_outputs,
            selected_coins, 
            destroy_selected_coins,
            inputs_with_amount,
            fresh_coinjoin_key,
            commit_transaction
        )));

        Self {
            id: unsafe { NEXT_ID }, 
            coinjoin: coinjoin,
            mixing_wallet: wallet_ex.clone(),
            base_session: CoinJoinBaseSession::new(),
            key_holder_storage: KeyHolderStorage::new(),
            options: options,
            state: PoolState::Idle,
            status: PoolStatus::Warmup,
            last_create_denominated_result: true,
            session_id: 0,
            outpoint_locked: Vec::new(),
            mixing_masternode: None,
            pending_dsa_request: None,
            tx_my_collateral: None,
            is_my_collateral_valid: false,
            collateral_session_map: HashMap::new(),
            str_auto_denom_result: String::new()
        }
    }

    pub fn do_automatic_denominating(&mut self, dry_run: bool, balance_info: Balance) -> bool {
        if self.state != PoolState::Idle || !self.options.enable_coinjoin {
            return false;
        }

        // if (getEntriesCount() > 0) { TODO: statuses
        //     setStatus(PoolStatus.MIXING);
        //     return false;
        // }

        if self.base_session.entries.len() > 0 {
            self.set_status(PoolStatus::Mixing);
            return false;
        }

        let balance_anonymized = balance_info.anonymized;
        let sub_res = (self.options.coinjoin_amount * DUFFS).checked_sub(balance_anonymized);
        
        if sub_res.is_none() {
            println!("[RUST] CoinJoinClientSession::do_automatic_denominating -- Nothing to do\n");
            // nothing to do, just keep it in idle mode
            self.set_status(PoolStatus::Finished);
            return false;
        }

        let mut balance_needs_anonymized = sub_res.unwrap();
        let mut value_min = CoinJoin::get_smallest_denomination();

        // if there are no confirmed DS collateral inputs yet
        if !self.mixing_wallet.borrow_mut().has_collateral_inputs(true) {
            println!("[RUST] CoinJoin: no collateral inputs");
            // should have some additional amount for them
            value_min = value_min + CoinJoin::get_max_collateral_amount();
        }

        // including denoms but applying some restrictions
        let balance_anonymizable = self.mixing_wallet.borrow_mut().get_anonymizable_balance(false, true);

         // mixable balance is way too small
         if balance_anonymizable < value_min {
            let balance_left_to_mix = self.mixing_wallet.borrow_mut().get_anonymizable_balance(false, false);
            
            if balance_left_to_mix < value_min {
                self.set_status(PoolStatus::ErrNotEnoughFunds);
                println!("[RUST] CoinJoin Err: NotEnoughFunds");
                // queueSessionCompleteListeners(getState(), ERR_SESSION); TODO: 
            }
            
            return false;
        }

        let balance_anonimizable_non_denom = self.mixing_wallet.borrow_mut().get_anonymizable_balance(true, true);
        let balance_denominated_conf = balance_info.denominated_trusted;
        let balance_denominated_unconf = balance_info.denominated_untrusted_pending;
        let balance_denominated = balance_denominated_conf + balance_denominated_unconf;
        let balance_to_denominate = self.options.coinjoin_amount.saturating_sub(balance_denominated);
        println!("[RUST] CoinJoin: balance_to_denominate: {}", balance_to_denominate);

        // Adjust balance_needs_anonymized to consume final denom
        if balance_denominated.saturating_sub(balance_anonymized) > balance_needs_anonymized as u64 {
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


        println!("[RUST] CoinJoin: wallet stats:\n{}", balance_info);
        println!("[RUST] CoinJoin: current stats:\nnValueMin: {}\n myTrusted: {}\n balanceAnonymizable: {}\n balanceAnonymized: {}\n balanceNeedsAnonymized: {}\n balanceAnonimizableNonDenom: {}\n balanceDenominatedConf: {}\n balanceDenominatedUnconf: {}\n balanceDenominated: {}\n balanceToDenominate: {}\n",
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
        self.last_create_denominated_result = true;
        
        if balance_anonimizable_non_denom >= value_min + CoinJoin::get_max_collateral_amount() && balance_to_denominate > 0 {
            self.last_create_denominated_result = self.create_denominated(balance_to_denominate, dry_run);
        }

        if dry_run {
            println!("[RUST] CoinJoin: create denominations {}, {}", self.last_create_denominated_result, dry_run);
            return self.last_create_denominated_result;
        }

        // check if we have the collateral sized inputs
        if !self.mixing_wallet.borrow_mut().has_collateral_inputs(true) {
            return !self.mixing_wallet.borrow_mut().has_collateral_inputs(false) && self.make_collateral_amounts();
        }

        if self.session_id != 0 {
            self.set_status(PoolStatus::Mixing);
            return false;
        }
        
        // Initial phase, find a Masternode
        // Clean if there is anything left from previous session
        self.unlock_coins();
        self.key_holder_storage.return_all();
        self.set_null();

        // should be no unconfirmed denoms in non-multi-session mode
        if !self.options.coinjoin_multi_session && balance_denominated_unconf > 0 {
            self.str_auto_denom_result = "Found unconfirmed denominated outputs, will wait till they confirm to continue.".to_string();
            println!("[RUST] CoinJoin: {}", self.str_auto_denom_result);
            return false;
        }

        let mut reason = String::new();
        match self.tx_my_collateral.clone() {
            None => {
                if !self.create_collateral_transaction(&mut reason) {
                    println!("[RUST] CoinJoin: create collateral error: {}", reason);
                    return false;
                }
            },
            Some(collateral) => {
                if !self.is_my_collateral_valid || !self.coinjoin.is_collateral_valid(&collateral, true) {
                    println!("[RUST] CoinJoin: invalid collateral, recreating... [id: {}] ", self.id);
                    let output = &collateral.outputs[0];
                    
                    if output.script_pub_key_type() == ScriptType::PayToPubkeyHash {
                        self.mixing_wallet.borrow_mut().add_unused_key(&output.script);
                    }

                    if !self.create_collateral_transaction(&mut reason) {
                        println!("[RUST] CoinJoin: create collateral error: {}", reason);
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

        println!("[RUST] CoinJoin: moved to queue joining/creating");

        // Always attempt to join an existing queue
        if self.join_existing_queue(balance_needs_anonymized) {
            return true;
        }

        // If we were unable to find/join an existing queue then start a new one.
        if self.start_new_queue(balance_needs_anonymized) {
            return true;
        }
        
        self.set_status(PoolStatus::WarnNoCompatibleMasternode);
        return false;
    }

    fn create_denominated(&mut self, balance_to_denominate: u64, dry_run: bool) -> bool {
        if !self.options.enable_coinjoin {
            return false;
        }

        println!("[RUST] CoinJoin: create_denominated");
    
        // NOTE: We do not allow txes larger than 100 kB, so we have to limit number of inputs here.
        // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
        // Knowing that each CTxIn is at least 148 B big, 400 inputs should take 400 x ~148 B = ~60 kB.
        // This still leaves more than enough room for another data of typical CreateDenominated tx.
        let mut vec_tally: Vec<CompactTallyItem> = self.mixing_wallet.borrow_mut().select_coins_grouped_by_addresses(true, true, true, 400);
    
        if vec_tally.is_empty() {
            println!("[RUST] CoinJoinClientSession::CreateDenominated -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
            return false;
        }
    
        // Start from the largest balances first to speed things up by creating txes with larger/largest denoms included
        vec_tally.sort_by(|a, b| b.amount.cmp(&a.amount));
        let create_mixing_collaterals = !self.mixing_wallet.borrow_mut().has_collateral_inputs(true);
        println!("[RUST] CoinJoin: has_collateral_inputs: {}", !create_mixing_collaterals);
    
        for item in vec_tally {
            if !self.create_denominated_with_item(&item, balance_to_denominate, create_mixing_collaterals, dry_run) {
                continue;
            }

            return true;
        }
    
        println!("[RUST] CoinJoinClientSession: createDenominated({}) -- failed! ", balance_to_denominate.to_friendly_string());
        false
    }

    fn create_denominated_with_item(
        &mut self, 
        tally_item: &CompactTallyItem, 
        balance_to_denominate: u64, 
        create_mixing_collaterals: bool, 
        dry_run: bool
    ) -> bool {
        if !self.options.enable_coinjoin {
            return false;
        }

        println!("[RUST] CoinJoin: create_denominated_with_item");

        // denominated input is always a single one, so we can check its amount directly and return early
        if tally_item.input_coins.len() == 1 && CoinJoin::is_denominated_amount(tally_item.amount) {
            return false;
        }

        let mut tx_builder = TransactionBuilder::new(
            self.mixing_wallet.clone(),
            self.options.chain_type,
            tally_item.clone(),
            dry_run
        );

        println!("[RUST] CoinJoin create_denominated_with_item. Start tx_builder: {}", tx_builder);

        // ****** Add an output for mixing collaterals ************ /

        if create_mixing_collaterals && !tx_builder.add_output(CoinJoin::get_max_collateral_amount()) {
            println!("[RUST] CoinJoinClientSession::CreateDenominatedWithItem -- Failed to add collateral output\n");
            return false;
        }

        // ****** Add outputs for denoms ************ /

        let mut add_final = true;
        let denoms = CoinJoin::get_standard_denominations();
        let mut map_denom_count = HashMap::new();

        for denom_value in denoms {
            map_denom_count.insert(*denom_value, self.mixing_wallet.borrow_mut().count_input_with_amount(*denom_value));
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
                let mut current_denom = map_denom_count[denom_value];
                let mut outputs = 0;

                let mut need_more_outputs = |tx_builder: &TransactionBuilder, balance_to_denominate: u64, outputs: i32| {
                    if tx_builder.could_add_output(*denom_value) {
                        if add_final && balance_to_denominate > 0 && balance_to_denominate < *denom_value {
                            add_final = false; // add final denom only once, only the smallest possible one
                            println!("[RUST] CoinJoinClientSession -- 1 - FINAL - nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                                denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                            true
                        } else if balance_to_denominate >= *denom_value {
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                };

                // add each output up to 11 times or until it can't be added again or until we reach nCoinJoinDenomsGoal
                while need_more_outputs(&tx_builder, balance_to_denominate, outputs) && outputs <= 10 && current_denom <  DEFAULT_COINJOIN_DENOMS_GOAL {
                    // Add output and subtract denomination amount
                    if tx_builder.add_output(*denom_value) {
                        outputs += 1;
                        current_denom += 1;
                        balance_to_denominate = balance_to_denominate.saturating_sub(*denom_value);
                        map_denom_count.insert(*denom_value, current_denom);
                        println!("[RUST] CoinJoinClientSession -- 2 - nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                            denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                    } else {
                        println!("[RUST] CoinJoinClientSession -- 2 - Error: AddOutput failed for nDenomValue: {}, nBalanceToDenominate: {}, nOutputs: {}, {}",
                            denom_value.to_friendly_string(), balance_to_denominate.to_friendly_string(), outputs, tx_builder.to_string());
                        return false;
                    }
                }

                if tx_builder.amount_left() == 0 || balance_to_denominate <= 0 {
                    break;
                }
            }

            let mut finished = true;

            for (denom, count) in &map_denom_count {
                // Check if this specific denom could use another loop, check that there aren't nCoinJoinDenomsGoal of this
                // denom and that our nValueLeft/nBalanceToDenominate is enough to create one of these denoms, if so, loop again.
                if *count < DEFAULT_COINJOIN_DENOMS_GOAL && tx_builder.could_add_output(*denom) && balance_to_denominate > 0 {
                    finished = false;
                    println!("[RUST] CoinJoinClientSession -- 1 - NOT finished - nDenomValue: {}, count: {}, nBalanceToDenominate: {}, {}",
                        denom.to_friendly_string(), count, balance_to_denominate.to_friendly_string(), tx_builder.to_string());
                    break;
                }
                println!("[RUST] CoinJoinClientSession -- 1 - FINISHED - nDenomValue: {}, count: {}, nBalanceToDenominate: {}, {}",
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
            println!("[RUST] CoinJoinClientSession -- 2 - Process remainder: {}\n", tx_builder.to_string());

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
                println!("[RUST] CoinJoinClientSession -- 2 - nBalanceToDenominate: {}, nDenomValue: {}, denomsToCreateValue: {}, denomsToCreateBal: {}\n",
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
                        println!("[RUST] CoinJoinClientSession -- 2 - Error: AddOutput failed at {}/{}, {}\n", i + 1, denoms_to_create, tx_builder.to_string());
                        break;
                    }

                    println!("[RUST] CoinJoinClientSession -- 2 - denomValue: {}, balanceToDenominate: {}, nOutputs: {}, {}\n",
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

        println!("[RUST] CoinJoinClientSession -- 3 - nBalanceToDenominate: {}, {}\n", balance_to_denominate.to_friendly_string(), tx_builder.to_string());

        for (denom, count) in &map_denom_count {
            println!("[RUST] CoinJoinClientSession -- 3 - DONE - nDenomValue: {}, count: {}\n", denom.to_friendly_string(), count);
        }

        // No reasons to create mixing collaterals if we can't create denoms to mix
        if (create_mixing_collaterals && tx_builder.outputs.len() == 1) || tx_builder.outputs.len() == 0 {
            return false;
        }

        if !dry_run {
            let mut str_result = String::new();
            
            if !tx_builder.commit(&mut str_result) {
                println!("[RUST] CoinJoinClientSession -- 4 - Commit failed: {}\n", str_result);
                return false;
            }

            // use the same nCachedLastSuccessBlock as for DS mixing to prevent race
            // m_manager.UpdatedSuccessBlock(); // TODO
            println!("[RUST] CoinJoinClientSession -- 4: {}\n", str_result);
        }

        return true;
    }

    fn make_collateral_amounts(&mut self) -> bool {
        if !self.options.enable_coinjoin {
            return false;
        }

        println!("[RUST] CoinJoin make_collateral_amounts");

        // NOTE: We do not allow txes larger than 100 kB, so we have to limit number of inputs here.
        // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
        // Knowing that each CTxIn is at least 148 B big, 400 inputs should take 400 x ~148 B = ~60 kB.
        // This still leaves more than enough room for another data of typical MakeCollateralAmounts tx.
        let mut vec_tally = self.mixing_wallet.borrow_mut().select_coins_grouped_by_addresses(false, false, true, 400);

        if vec_tally.is_empty() {
            println!("[RUST] CoinJoinClientSession::MakeCollateralAmounts -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
            return false;
        }

        // Start from the smallest balances first to consume tiny amounts and cleanup UTXO a bit
        vec_tally.sort_by(|a, b| a.amount.cmp(&b.amount));

        // First try to use only non-denominated funds
        for item in &vec_tally {
            if !self.make_collateral_amounts_with_item(item, false) {
                continue;
            }

            return true;
        }

        // There should be at least some denominated funds we should be able to break in pieces to continue mixing
        for item in &vec_tally {
            if !self.make_collateral_amounts_with_item(item, true) {
                continue;
            }

            return true;
        }

        // If we got here then something is terribly broken actually
        println!("[RUST] CoinJoinClientSession::MakeCollateralAmounts -- ERROR: Can't make collaterals!\n");
        return false;
    }

    fn make_collateral_amounts_with_item(&mut self, tally_item: &CompactTallyItem, try_denominated: bool) -> bool {
        if !self.options.enable_coinjoin {
            return false;
        }

        println!("[RUST] CoinJoin make_collateral_amounts_with_item: {:?}", tally_item);

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
            self.options.chain_type,
            tally_item.clone(),
            false
        );
        println!("[RUST] CoinJoin make_collateral_amounts_with_item. Start tx_builder {}", tx_builder);
        
        // Skip way too tiny amounts. Smallest we want is minimum collateral amount in a one output tx
        if !tx_builder.could_add_output(CoinJoin::get_collateral_amount()) {
            return false;
        }

        let case; // Just for debug logs

        if tx_builder.could_add_outputs(&[CoinJoin::get_max_collateral_amount(), CoinJoin::get_collateral_amount()].to_vec()) {
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
        } else if tx_builder.could_add_outputs(&[CoinJoin::get_collateral_amount(), CoinJoin::get_collateral_amount()].to_vec()) {
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

        println!("[RUST] CoinJoin: Done with case {}: {}", case, tx_builder);
        println!("[RUST] CoinJoin: is_dust: {}", TransactionBuilder::is_dust(tx_builder.amount_left()));
        assert!(TransactionBuilder::is_dust(tx_builder.amount_left()));

        let mut str_result = String::new();

        if !tx_builder.commit(&mut str_result) {
            println!("[RUST] CoinJoin: Commit failed: {}", str_result);
            return false;
        }

        // mixingWallet.getContext().coinJoinManager.coinJoinClientManagers.get(mixingWallet.getDescription()).updatedSuccessBlock(); TODO
        // log.info("coinjoin: txid: {}", strResult);
        // queueTransactionListeners(txBuilder.getTransaction(), CoinJoinTransactionType.MakeCollateralInputs);

        return true;
    }


    pub fn set_status(&self, pool_status: PoolStatus) {
        // TODO
            // strAutoDenomResult = CoinJoin.getStatusById(poolStatus);
            // if (poolStatus.isError())
            //     log.error("coinjoin: {}", strAutoDenomResult);
            // else if (poolStatus.isWarning())
            //     log.warn("coinjoin: {}", strAutoDenomResult);
            // else
            //     log.info("coinjoin: {}", strAutoDenomResult);
    
            // status.set(poolStatus);
            // if (poolStatus.shouldStop()) {
            //     log.info("Session has nothing to do: {}", poolStatus);
            //     if (poolStatus.isError())
            //         log.error("Session has an error: {}", poolStatus);
            //     hasNothingToDo.set(true);
            // }
    }

    fn unlock_coins(&mut self) {
        if !self.options.enable_coinjoin {
            return;
        }

        for outpoint in &self.outpoint_locked {
            self.mixing_wallet.borrow_mut().unlock_coin(outpoint);
        }

        self.outpoint_locked.clear();
    }

    fn set_null(&mut self) {
        // if (mixingMasternode != null) { TODO
        //     if (context.coinJoinManager.isMasternodeOrDisconnectRequested(mixingMasternode.getService())) {
        //         if (!context.coinJoinManager.disconnectMasternode(mixingMasternode)) {
        //             log.info("not closing existing masternode: {}", mixingMasternode.getService().getSocketAddress());
        //         }
        //     } else {
        //         log.info("not closing masternode since it is not found: {}", mixingMasternode.getService().getSocketAddress());
        //     }
        // }
        self.mixing_masternode = None;
        self.pending_dsa_request = None;
        self.base_session.set_null();
    }

    fn create_collateral_transaction(&mut self, str_reason: &mut String) -> bool {
        println!("[RUST] CoinJoinClientSession::create_collateral_transaction");
        
        let mut coin_control = CoinControl::new();
        coin_control.coin_type = CoinType::OnlyCoinJoinCollateral;
        let coins = self.mixing_wallet.borrow_mut().availalbe_coins(true, coin_control);

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
            signature: None, 
            sequence: 0 // TODO: recheck
        }];
        let mut tx_collateral = Transaction {
            inputs: inputs,
            outputs: Vec::new(),
            lock_time: 0,
            version: 0,
            tx_hash: None,
            tx_type: TransactionType::Classic,
            payload_offset: 0,
            block_height: 0, // TODO: recheck
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

        println!("[RUST] CoinJoin before signing: {:?}", tx_collateral);
        if let Some(signed_tx) = self.mixing_wallet.borrow().sign_transaction(&tx_collateral) {
            println!("[RUST] CoinJoin after signing: {:?}", signed_tx);

            if let Some(tx_id) = signed_tx.tx_hash {
                self.tx_my_collateral = Some(signed_tx);
                self.is_my_collateral_valid = true;

                if !self.collateral_session_map.contains_key(&tx_id) {
                    self.collateral_session_map.insert(tx_id, 0);
                }
            }

            return true;
        }

        println!("[RUST] CoinJoin: Unable to sign collateral transaction!");
        str_reason.push_str("Unable to sign collateral transaction!");

        return false;
    }

    fn join_existing_queue(&self, balance_needs_anonymized: u64) -> bool {
        // TODO

        return false;
    }

    fn start_new_queue(&self, balance_needs_anonymized: u64) -> bool {
        // TODO

        return false;
    }
}
