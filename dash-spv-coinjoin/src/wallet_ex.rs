use std::collections::{HashSet, HashMap};
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use byte::{BytesExt, LE};
use dash_spv_masternode_processor::consensus::Encodable;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::crypto::byte_util::Reversable;
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput};
use ferment_interfaces::boxed;

use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::ffi::callbacks::{DestroySelectedCoins, DestroyWalletTransaction, GetWalletTransaction, HasCollateralInputs, IsMineInput, SelectCoinsGroupedByAddresses, SignTransaction};
use crate::coinjoin::CoinJoin;
use crate::constants::MAX_COINJOIN_ROUNDS;
use crate::models::tx_outpoint::TxOutPoint;
use crate::models::CoinJoinClientOptions;

#[derive(Debug)]
pub struct WalletEx {
    opaque_context: *const std::ffi::c_void,
    options: CoinJoinClientOptions,
    pub locked_coins_set: HashSet<TxOutPoint>,
    anonymizable_tally_cached_non_denom: bool,
    vec_anonymizable_tally_cached_non_denom: Vec<CompactTallyItem>, // TODO: is there a better way to cache?
    anonymizable_tally_cached: bool,
    vec_anonymizable_tally_cached: Vec<CompactTallyItem>,
    map_outpoint_rounds_cache: HashMap<TxOutPoint, i32>,
    coinjoin_salt: UInt256,
    get_wallet_transaction: GetWalletTransaction,
    destroy_wallet_transaction: DestroyWalletTransaction,
    is_mine_input: IsMineInput,
    has_collateral_inputs: HasCollateralInputs,
    select_coins: SelectCoinsGroupedByAddresses,
    destroy_selected_coins: DestroySelectedCoins
}

impl WalletEx {
    pub fn new(
        opaque_context: *const std::ffi::c_void,
        options: CoinJoinClientOptions,
        get_wallet_transaction: GetWalletTransaction,
        destroy_wallet_transaction: DestroyWalletTransaction,
        is_mine_input: IsMineInput,
        has_collateral_inputs: HasCollateralInputs,
        select_coins: SelectCoinsGroupedByAddresses,
        destroy_selected_coins: DestroySelectedCoins
    ) -> Self {
        WalletEx {
            opaque_context,
            options,
            locked_coins_set: HashSet::new(),
            anonymizable_tally_cached_non_denom: false,
            vec_anonymizable_tally_cached_non_denom: Vec::new(),
            anonymizable_tally_cached: false,
            vec_anonymizable_tally_cached: Vec::new(),
            map_outpoint_rounds_cache: HashMap::new(),
            coinjoin_salt: UInt256([0;32]), // TODO: InitCoinJoinSalt ?
            get_wallet_transaction,
            destroy_wallet_transaction,
            is_mine_input,
            has_collateral_inputs,
            select_coins,
            destroy_selected_coins
        }
    }

    pub fn lock_coin(&mut self, outpoint: TxOutPoint) {
        self.locked_coins_set.insert(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn unlock_coin(&mut self, outpoint: &TxOutPoint) {
        self.locked_coins_set.remove(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn is_fully_mixed(&mut self, outpoint: TxOutPoint) -> bool {
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
            buffer.extend_from_slice(&self.coinjoin_salt.reversed().0);
            let hash = UInt256::sha256(&buffer);

            if &hash.0.read_with::<u32>(&mut 0, LE).unwrap() % 2 == 0 {
                return false;
            }
        }

        true
    }


    pub fn get_real_outpoint_coinjoin_rounds(&mut self, outpoint: TxOutPoint, rounds: i32) -> i32 {
        let rounds_max = MAX_COINJOIN_ROUNDS + self.options.coinjoin_random_rounds;

        if rounds >= rounds_max {
            // there can only be rounds_max rounds max
            return rounds_max - 1;
        }

        let mut rounds_ref = *self.map_outpoint_rounds_cache.entry(outpoint.clone()).or_insert(-10);

        if rounds_ref != -10 {
            return rounds_ref;
        }

        let wtx: Option<Transaction> = self.get_wallet_transaction(outpoint.hash);

        if wtx.is_none() {
            // no such tx in this wallet
            rounds_ref = -1;
            println!("FAILED    {:?} {} (no such tx)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        let transaction = wtx.unwrap();
        // bounds check
        if outpoint.index >= transaction.outputs.len() as u32 {
            // should never actually hit this
            rounds_ref = -4;
            println!("FAILED    {:?} {} (bad index)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        let tx_out = &transaction.outputs[outpoint.index as usize];

        if CoinJoin::is_collateral_amount(tx_out.amount) {
            rounds_ref = -3;
            println!("UPDATED    {:?} {} (collateral)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        // make sure the final output is non-denominate
        if !CoinJoin::is_denominated_amount(tx_out.amount) {
            rounds_ref = -2;
            println!("UPDATED    {:?} {} (non-denominated)", outpoint, rounds_ref);
            self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
            return rounds_ref;
        }

        for out in &transaction.outputs {
            if !CoinJoin::is_denominated_amount(out.amount) {
                // this one is denominated but there is another non-denominated output found in the same tx
                rounds_ref = 0;
                println!("UPDATED    {:?} {} (non-denominated)", outpoint, rounds_ref);
                self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
                return rounds_ref;
            }
        }

        let mut n_shortest = -10; // an initial value, should be no way to get this by calculations
        let mut denom_found = false;

        // only denoms here so let's look up
        for txin_next in &transaction.inputs {
            if self.is_mine_input(&txin_next) {
                let outpoint = TxOutPoint::new(txin_next.input_hash, txin_next.index);
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

        println!("UPDATED    {:?} {} (coinjoin)", outpoint, rounds_ref);
        self.map_outpoint_rounds_cache.insert(outpoint, rounds_ref);
        rounds_ref
    }

    pub fn has_collateral_inputs(&mut self, only_confirmed: bool) -> bool {
        unsafe { (self.has_collateral_inputs)(only_confirmed, self, self.opaque_context) }
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
                println!("[RUST] CoinJoin: SelectCoinsGroupedByAddresses - using cache for non-denom inputs {}", self.vec_anonymizable_tally_cached_non_denom.len());
                return self.vec_anonymizable_tally_cached_non_denom.clone();
            }

            if !skip_denominated && self.anonymizable_tally_cached {
                println!("[RUST] CoinJoin: SelectCoinsGroupedByAddresses - using cache for all inputs {}", self.vec_anonymizable_tally_cached.len());
                return self.vec_anonymizable_tally_cached.clone();
            }
        }
        
        let mut vec_tally_ret: Vec<CompactTallyItem> = Vec::new();

        unsafe {
            let selected_coins = (self.select_coins)(skip_denominated, anonymizable, skip_unconfirmed, max_outpoints_per_address, self, self.opaque_context);

            (0..(*selected_coins).item_count)
                .into_iter()
                .map(|i| (**(*selected_coins).items.add(i)).decode())
                .for_each(
                    |item| vec_tally_ret.push(item)
                );

            (self.destroy_selected_coins)(selected_coins);
        }

        // Cache already confirmed mixable entries for later use.
        // This should only be used if nMaxOupointsPerAddress was NOT specified.
        if max_outpoints_per_address == -1 && anonymizable && skip_unconfirmed {
            if skip_denominated {
                self.vec_anonymizable_tally_cached_non_denom = vec_tally_ret.clone();
                self.anonymizable_tally_cached_non_denom = true;
            } else {
                self.vec_anonymizable_tally_cached = vec_tally_ret.clone();
                self.anonymizable_tally_cached = true;
            }
        }
        
        // debug
//            StringBuilder strMessage = new StringBuilder("vecTallyRet:\n");
//            for (CompactTallyItem item :vecTallyRet)
//                strMessage.append(String.format("  %s %s\n", item.txDestination, item.amount.toFriendlyString()));
//            log.info(strMessage.toString()); /* Continued */

        return vec_tally_ret;
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
                total = total + item.amount;
            }
        }

        return total;
    }

    pub fn get_wallet_transaction(&self, hash: UInt256) -> Option<Transaction> {
        unsafe {
            let wtx = (self.get_wallet_transaction)(boxed(hash.0), self.opaque_context);
            
            if wtx.is_null() {
                return None;
            }
            
            let transaction = (*wtx).decode();
            (self.destroy_wallet_transaction)(wtx);
            Some(transaction)
        }
    }

    fn clear_anonymizable_caches(&mut self) {
        self.anonymizable_tally_cached_non_denom = false;
        self.anonymizable_tally_cached = false;
    }

    fn is_mine_input(&self, txin: &TransactionInput) -> bool {
        unsafe { (self.is_mine_input)(boxed(txin.input_hash.0), txin.index, self.opaque_context) }
    }
}
