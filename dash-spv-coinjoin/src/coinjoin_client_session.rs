use std::fmt::Debug;

use dash_spv_masternode_processor::chain::params::DUFFS;
use dash_spv_masternode_processor::models::MasternodeEntry;
use dash_spv_masternode_processor::tx::Transaction;
use dash_spv_masternode_processor::util::script::ScriptType;

use crate::coinjoin::CoinJoin;
use crate::models::tx_outpoint::TxOutPoint;
use crate::messages::{pool_state::PoolState, pool_status::PoolStatus};
use crate::models::pending_dsa_request::PendingDsaRequest;
use crate::models::{CoinJoinClientOptions, Balance};
use crate::coinjoin_base_session::CoinJoinBaseSession;
use crate::utils::coin_format::CoinFormat;
use crate::utils::key_holder_storage::KeyHolderStorage;
use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::wallet_ex::WalletEx;

static mut NEXT_ID: i32 = 0;

#[derive(Debug)]
pub struct CoinJoinClientSession {
    id: i32,
    coinjoin: CoinJoin,
    mixing_wallet: WalletEx,
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
    str_auto_denom_result: String
}

impl CoinJoinClientSession {
    pub fn new(
        coinjoin: CoinJoin,
        wallet_ex: WalletEx,
        options: CoinJoinClientOptions,
    ) -> Self {
        unsafe { NEXT_ID += 1; } // TODO

        Self {
            id: unsafe { NEXT_ID }, 
            coinjoin: coinjoin,
            mixing_wallet: wallet_ex,
            base_session: CoinJoinBaseSession::new(),
            options: options,
            key_holder_storage: KeyHolderStorage::new(),
            state: PoolState::Idle,
            status: PoolStatus::Warmup,
            last_create_denominated_result: true,
            session_id: 0,
            outpoint_locked: Vec::new(),
            mixing_masternode: None,
            pending_dsa_request: None,
            tx_my_collateral: None,
            is_my_collateral_valid: false,
            str_auto_denom_result: String::new()
        }
    }

    pub fn do_automatic_denominating(&self, dry_run: bool, balance_info: Balance) -> bool {
        if self.state != PoolState::Idle || !self.options.enable_coinjoin {
            return false;
        }

        // if (getEntriesCount() > 0) {
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
            println!("CoinJoinClientSession::do_automatic_denominating -- Nothing to do\n");
            // nothing to do, just keep it in idle mode
            self.set_status(PoolStatus::Finished);
            return false;
        }

        let balance_needs_anonymized = sub_res.unwrap();
        let mut value_min = CoinJoin::get_smallest_denomination();

        // if there are no confirmed DS collateral inputs yet
        if !self.mixing_wallet.has_collateral_inputs(true) {
            // should have some additional amount for them
            value_min = value_min + CoinJoin::get_max_collateral_amount();
        }

        // including denoms but applying some restrictions
        let balance_anonymizable = self.mixing_wallet.get_anonymizable_balance(false, true);

         // mixable balance is way too small
         if balance_anonymizable < value_min {
            let balance_left_to_mix = self.mixing_wallet.get_anonymizable_balance(false, false);
            
            if balance_left_to_mix < value_min {
                self.set_status(PoolStatus::ErrNotEnoughFunds);
                // queueSessionCompleteListeners(getState(), ERR_SESSION); TODO: 
            }
            
            return false;
        }

        let balance_anonimizable_non_denom = self.mixing_wallet.get_anonymizable_balance(true);
        let balance_denominated_conf = balance_info.denominated_trusted;
        let balance_denominated_unconf = balance_info.denominated_untrusted_pending;
        let balance_denominated = balance_denominated_conf + balance_denominated_unconf;
        let balance_to_denominate = self.options.coinjoin_amount * DUFFS - balance_denominated;

        // Adjust balance_needs_anonymized to consume final denom
        if balance_denominated - balance_anonymized > balance_needs_anonymized as u64 {
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


        println!("coinjoin: wallet stats:\n{}", balance_info);
        println!("coinjoin: current stats:\nnValueMin: {}\n myTrusted: {}\n balanceAnonymizable: {}\n balanceAnonymized: {}\n balanceNeedsAnonymized: {}\n balanceAnonimizableNonDenom: {}\n balanceDenominatedConf: {}\n balanceDenominatedUnconf: {}\n balanceDenominated: {}\n balanceToDenominate: {}\n",
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
        if !self.mixing_wallet.has_collateral_inputs(true) {
            return !self.mixing_wallet.has_collateral_inputs(false) && self.make_collateral_amounts();
        }

        if self.session_id != 0 {
            self.set_status(PoolStatus::Mixing);
            return false;
        }
        
        // Initial phase, find a Masternode
        // Clean if there is anything left from previous session
        self.unlock_coins();
        // self.key_holder_storage.return_all(); TODO
        self.set_null();

        // should be no unconfirmed denoms in non-multi-session mode
        if !self.options.coinjoin_multi_session && balance_denominated_unconf > 0 {
            self.str_auto_denom_result = "Found unconfirmed denominated outputs, will wait till they confirm to continue.".to_string();
            println!("coinjoin: {}", self.str_auto_denom_result);
            return false;
        }

        let mut reason = String::new();
        match self.tx_my_collateral {
            None => {
                if !self.create_collateral_transaction(&mut reason) {
                    println!("coinjoin: create collateral error: {}", reason);
                    return false;
                }
            },
            Some(collateral) => {
                if !self.is_my_collateral_valid || !self.coinjoin.is_collateral_valid(&collateral, true) {
                    println!("coinjoin: invalid collateral, recreating... [id: {}] ", self.id);
                    let output = collateral.outputs[0];
                    
                    if output.script_pub_key_type() == ScriptType::PayToPubkeyHash {
                        // TODO
                        // mixingWallet.getCoinJoin().addUnusedKey(KeyId.fromBytes(ScriptPattern.extractHashFromP2PKH(output.getScriptPubKey()), false));
                    }

                    if !self.create_collateral_transaction(&mut reason) {
                        println!("coinjoin: create collateral error: {}", reason);
                        return false;
                    }
                }

                // lock the funds we're going to use for our collateral
                for txin in collateral.inputs {
                    let outpoint = TxOutPoint::new(txin.input_hash, txin.index);
                    self.mixing_wallet.lock_coin(outpoint.clone());
                    self.outpoint_locked.push(outpoint);
                }
            },
        }

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
    
        // NOTE: We do not allow txes larger than 100 kB, so we have to limit number of inputs here.
        // We still want to consume a lot of inputs to avoid creating only smaller denoms though.
        // Knowing that each CTxIn is at least 148 B big, 400 inputs should take 400 x ~148 B = ~60 kB.
        // This still leaves more than enough room for another data of typical CreateDenominated tx.
        let mut vec_tally: Vec<CompactTallyItem> = self.mixing_wallet.select_coins_grouped_by_addresses(true, true, true, 400);
    
        if vec_tally.is_empty() {
            println!("[RUST] CoinJoinClientSession::CreateDenominated -- SelectCoinsGroupedByAddresses can't find any inputs!\n");
            return false;
        }
    
        // Start from the largest balances first to speed things up by creating txes with larger/largest denoms included
        vec_tally.sort_by(|a, b| b.amount.cmp(&a.amount));
        let create_mixing_collaterals = !self.mixing_wallet.has_collateral_inputs(true);
    
        for item in vec_tally {
            if !self.create_denominated_with_item(&item, balance_to_denominate, create_mixing_collaterals, dry_run) {
                continue;
            }

            return true;
        }
    
        println!("coinjoin: createDenominated({}) -- failed! ", balance_to_denominate.to_friendly_string());
        false
    }

    fn create_denominated_with_item(&self, tally_item: &CompactTallyItem, balance_to_denominate: u64, create_mixing_collaterals: bool, dry_run: bool) -> bool {

        // TODO
        return true;
    }

    fn make_collateral_amounts(&self) -> bool {
        // TODO
        return false;
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
            self.mixing_wallet.unlock_coin(outpoint);
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

    fn create_collateral_transaction(&self, str_reason: &mut String) -> bool {
        // TODO

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
