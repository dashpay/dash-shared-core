use std::collections::{HashSet, HashMap};
use byte::{BytesExt, LE};
use dash_spv_masternode_processor::consensus::Encodable;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::crypto::byte_util::Reversable;
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput};
use ferment_interfaces::boxed;

use crate::callbacks::{GetWalletTransaction, DestroyWalletTransaction, IsMineInput};
use crate::messages::transaction_outpoint::TransactionOutPoint;
use crate::coinjoin::CoinJoin;
use crate::constants::MAX_COINJOIN_ROUNDS;
use crate::models::CoinJoinClientOptions;

#[derive(Debug)]
pub struct WalletEx {
    opaque_context: *const std::ffi::c_void,
    options: CoinJoinClientOptions,
    locked_coins_set: HashSet<TransactionOutPoint>,
    anonymizable_tally_cached_non_denom: bool,
    anonymizable_tally_cached: bool,
    map_outpoint_rounds_cache: HashMap<TransactionOutPoint, i32>,
    coinjoin_salt: UInt256,
    get_wallet_transaction: GetWalletTransaction,
    destroy_wallet_transaction: DestroyWalletTransaction,
    is_mine_input: IsMineInput
}

impl WalletEx {
    pub fn new(
        opaque_context: *const std::ffi::c_void,
        options: CoinJoinClientOptions,
        get_wallet_transaction: GetWalletTransaction,
        destroy_wallet_transaction: DestroyWalletTransaction,
        is_mine_input: IsMineInput
    ) -> Self {
        WalletEx {
            opaque_context,
            options,
            locked_coins_set: HashSet::new(),
            anonymizable_tally_cached_non_denom: false,
            anonymizable_tally_cached: false,
            map_outpoint_rounds_cache: HashMap::new(),
            coinjoin_salt: UInt256([0;32]), // TODO: InitCoinJoinSalt ?
            get_wallet_transaction,
            destroy_wallet_transaction,
            is_mine_input,
        }
    }

    pub fn lock_coin(&mut self, outpoint: TransactionOutPoint) {
        self.locked_coins_set.insert(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn unlock_coin(&mut self, outpoint: &TransactionOutPoint) {
        self.locked_coins_set.remove(outpoint);
        self.clear_anonymizable_caches();
    }

    pub fn is_fully_mixed(&mut self, outpoint: TransactionOutPoint) -> bool {
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


    pub fn get_real_outpoint_coinjoin_rounds(&mut self, outpoint: TransactionOutPoint, rounds: i32) -> i32 {
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
                let outpoint = TransactionOutPoint::new(txin_next.input_hash, txin_next.index);
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

    fn clear_anonymizable_caches(&mut self) {
        self.anonymizable_tally_cached_non_denom = false;
        self.anonymizable_tally_cached = false;
    }

    fn get_wallet_transaction(&self, hash: UInt256) -> Option<Transaction> {
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

    fn is_mine_input(&self, txin: &TransactionInput) -> bool {
        unsafe { (self.is_mine_input)(boxed(txin.input_hash.0), txin.index, self.opaque_context) }
    }
}
