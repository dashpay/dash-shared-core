use std::collections::HashMap;

use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::chain::params::DUFFS;
use dash_spv_masternode_processor::common::Block;
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use dash_spv_masternode_processor::tx::transaction::Transaction;
use dash_spv_masternode_processor::util::script::ScriptType;
use ferment_interfaces::boxed;

use crate::ffi::callbacks::{GetInputValueByPrevoutHash, HasChainLock, DestroyInputValue};
use crate::ffi::input_value::InputValue;
use crate::messages::pool_message::PoolMessage;
use crate::messages::pool_status::PoolStatus;
use crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use crate::constants::COINJOIN_ENTRY_MAX_SIZE;
use crate::utils::coin_format::CoinFormat;

#[derive(Debug)]
// #[ferment_macro::export]
pub struct CoinJoin {
    pub opaque_context: *const std::ffi::c_void,
    pub get_input_value_by_prevout_hash: GetInputValueByPrevoutHash,
    pub has_chain_lock: HasChainLock,
    pub destroy_input_value: DestroyInputValue,
    map_dstx: HashMap<UInt256, CoinJoinBroadcastTx>, // TODO: thread safety?
}

impl CoinJoin {
    // this list of standard denominations cannot be modified and must remain the same as
    // CoinJoin::vecStandardDenominations in coinjoin.cpp
    const STANDARD_DENOMINATIONS: [u64; 5] = [
        (10 * DUFFS) + 10000,
        (1 * DUFFS) + 1000,
        (DUFFS / 10) + 100,
        (DUFFS / 100) + 10,
        (DUFFS / 1000) + 1,
    ];

    pub fn new(
        get_input_value_by_prevout_hash: GetInputValueByPrevoutHash,
        has_chain_lock: HasChainLock,
        destroy_input_value: DestroyInputValue,
        context: *const std::ffi::c_void
    ) -> Self {
        Self {
            opaque_context: context,
            get_input_value_by_prevout_hash,
            has_chain_lock,
            destroy_input_value,
            map_dstx: HashMap::new()
        }
    }

    pub fn get_standard_denominations() -> &'static [u64] {
        &Self::STANDARD_DENOMINATIONS
    }

    pub fn get_smallest_denomination() -> u64 {
        Self::STANDARD_DENOMINATIONS[Self::STANDARD_DENOMINATIONS.len() - 1]
    }

    pub fn is_denominated_amount(input_amount: u64) -> bool {
        Self::amount_to_denomination(input_amount) > 0
    }

    pub fn is_valid_denomination(n_denom: u32) -> bool {
        Self::denomination_to_amount(n_denom) > 0
    }

    /// Return a bitshifted integer representing a denomination in STANDARD_DENOMINATIONS
    /// or 0 if none was found
    pub fn amount_to_denomination(input_amount: u64) -> u32 {
        for (i, &denom) in Self::STANDARD_DENOMINATIONS.iter().enumerate() {
            if input_amount == denom {
                return 1 << i;
            }
        }

        return 0;
    }

    /// # Returns
    /// - one of standard denominations from STANDARD_DENOMINATIONS based on the provided bitshifted integer
    /// - 0 for non-initialized sessions (nDenom = 0)
    /// - a value below 0 if an error occurred while converting from one to another
    pub fn denomination_to_amount(n_denom: u32) -> i64 {
        if n_denom == 0 {
            // not initialized
            return 0;
        }
    
        let n_max_denoms = Self::STANDARD_DENOMINATIONS.len();
    
        if n_denom >= (1 << n_max_denoms) {
            // out of bounds
            return -1;
        }
    
        if n_denom & (n_denom - 1) != 0 {
            // non-denom
            return -2;
        }
    
        let mut n_denom_amount = -3;
    
        for i in 0..n_max_denoms {
            if n_denom & (1 << i) != 0 {
                n_denom_amount = Self::STANDARD_DENOMINATIONS[i] as i64;
                break;
            }
        }
    
        n_denom_amount
    }

    pub fn max_pool_amount() -> u64 {
        Self::STANDARD_DENOMINATIONS[0] * COINJOIN_ENTRY_MAX_SIZE
    }    

    pub fn denomination_to_string(denom: u32) -> String {
        match Self::denomination_to_amount(denom) {
            0 => "N/A".to_string(),
            -1 => "out-of-bounds".to_string(),
            -2 => "non-denom".to_string(),
            -3 => "to-amount-error".to_string(),
            n => n.to_friendly_string(),
        }
    }

    // check to make sure the collateral provided by the client is valid
    pub fn is_collateral_valid(&self, tx_collateral: &Transaction, check_inputs: bool) -> bool {
        if tx_collateral.outputs.is_empty() {
            // TODO: logs
            println!("[RUST] CoinJoin: Collateral invalid due to no outputs: {}", tx_collateral.tx_hash.unwrap_or_default());
            return false;
        }

        if tx_collateral.lock_time != 0 {
            println!("[RUST] CoinJoin: Collateral invalid due to lock time != 0: {}", tx_collateral.tx_hash.unwrap_or_default());
            return false;
        }
    
        let mut n_value_in: i64 = 0;
        let mut n_value_out: i64 = 0;
    
        for txout in &tx_collateral.outputs {
            n_value_out = n_value_out + txout.amount as i64;
    
            if txout.script_pub_key_type() != ScriptType::PayToPubkeyHash && !txout.is_script_unspendable() {
                println!("[RUST] CoinJoin: Invalid Script, txCollateral={}", tx_collateral.tx_hash().unwrap_or_default());
                return false;
            }
        }
    
        if check_inputs {
            for txin in &tx_collateral.inputs {
                let result = self.get_input_value_by_prevout_hash(txin.input_hash, txin.index);
                
                if let Some(input_value) = result {
                    if !input_value.is_valid {
                        println!("[RUST] CoinJoin: spent or non-locked mempool input! txin={:?}", txin);
                       return false;
                    }

                    n_value_in = n_value_in + input_value.value as i64;
                } else {
                    println!("[RUST] CoinJoin: -- Unknown inputs in collateral transaction, txCollateral={}", tx_collateral.tx_hash().unwrap_or_default());
                    return false;
                }
            }

            println!("[RUST] CoinJoin: n_value_out={}, n_value_in={}", n_value_out, n_value_in);

            if n_value_in - n_value_out < CoinJoin::get_collateral_amount() as i64 {
                println!("[RUST] CoinJoin: did not include enough fees in transaction: fees: {}, txCollateral={}", n_value_out - n_value_in, tx_collateral.tx_hash().unwrap_or_default());
                return false;
            }
        }
    
        true
    }

    pub fn get_collateral_amount() -> u64 { Self::get_smallest_denomination() / 10 }
    pub fn get_max_collateral_amount() -> u64 { Self::get_collateral_amount() * 4 }

    pub fn is_collateral_amount(input_amount: u64) -> bool {
        input_amount >= Self::get_collateral_amount() && input_amount <= Self::get_max_collateral_amount()
    }

    pub fn calculate_amount_priority(input_amount: u64) -> i64 {
        let mut opt_denom = 0;

        for denom in Self::get_standard_denominations() {
            if input_amount == *denom {
                opt_denom = *denom;
            }
        }

        if opt_denom > 0 {
            return (DUFFS as f64 / opt_denom as f64 * 10000.0) as i64;
        }

        if input_amount < DUFFS {
            return 20000;
        }

        // nondenom return largest first
        -1 * (input_amount / DUFFS) as i64
    }

    pub fn check_dstxs(&mut self, block: Block) {
        self.map_dstx.retain(|_, tx| !tx.is_expired(block, self.has_chain_lock, self.opaque_context));
    }

    pub fn add_dstx(&mut self, dstx: CoinJoinBroadcastTx) {
        if let Some(tx_hash) = dstx.tx.tx_hash {
            self.map_dstx.insert(tx_hash, dstx);
        }
    }

    pub fn has_dstx(&self, tx_hash: UInt256) -> bool {
        self.map_dstx.contains_key(&tx_hash)
    }

    pub fn get_dstx(&self, tx_hash: UInt256) -> Option<&CoinJoinBroadcastTx> {
        self.map_dstx.get(&tx_hash)
    }

    pub fn update_block_tip(&mut self, block: Block) {
        self.check_dstxs(block);
    }

    pub fn notify_chain_lock(&mut self, block: Block) {
        self.check_dstxs(block);
    }

    pub fn update_dstx_confirmed_height(&mut self, tx_hash: UInt256, n_height: i32) {
        if let Some(broadcast_tx) = self.map_dstx.get_mut(&tx_hash) {
            broadcast_tx.set_confirmed_height(n_height);
        }
    }

    pub fn transaction_added_to_mempool(&mut self, tx_hash: UInt256) {
        self.update_dstx_confirmed_height(tx_hash, -1);
    }

    pub fn block_connected(&mut self, block_height: u32, block_transactions: Vec<UInt256>, vtx_conflicted: Vec<UInt256>) {
        for tx_hash in vtx_conflicted {
            self.update_dstx_confirmed_height(tx_hash, -1);
        }

        for tx_hash in block_transactions {
            self.update_dstx_confirmed_height(tx_hash, block_height as i32);
        }
    }

    pub fn block_disconnected(&mut self, block_transactions: Vec<UInt256>,) {
        for tx_hash in block_transactions {
            self.update_dstx_confirmed_height(tx_hash, -1);
        }
    }

    pub fn get_message_by_id(message_id: PoolMessage) -> &'static str {
        match message_id {
            PoolMessage::ErrAlreadyHave => "Already have that input.",
            PoolMessage::ErrDenom => "No matching denominations found for mixing.",
            PoolMessage::ErrEntriesFull => "Entries are full.",
            PoolMessage::ErrExistingTx => "Not compatible with existing transactions.",
            PoolMessage::ErrFees => "Transaction fees are too high.",
            PoolMessage::ErrInvalidCollateral => "Collateral not valid.",
            PoolMessage::ErrInvalidInput => "Input is not valid.",
            PoolMessage::ErrInvalidScript => "Invalid script detected.",
            PoolMessage::ErrInvalidTx => "Transaction not valid.",
            PoolMessage::ErrMaximum => "Entry exceeds maximum size.",
            PoolMessage::ErrMnList => "Not in the Masternode list.",
            PoolMessage::ErrMode => "Incompatible mode.",
            PoolMessage::ErrQueueFull => "Masternode queue is full.",
            PoolMessage::ErrRecent => "Last queue was created too recently.",
            PoolMessage::ErrSession => "Session not complete!",
            PoolMessage::ErrMissingTx => "Missing input transaction information.",
            PoolMessage::ErrVersion => "Incompatible version.",
            PoolMessage::MsgNoErr => "No errors detected.",
            PoolMessage::MsgSuccess => "Transaction created successfully.",
            PoolMessage::MsgEntriesAdded => "Your entries added successfully.",
            PoolMessage::ErrSizeMismatch => "Inputs vs outputs size mismatch.",
            PoolMessage::ErrTimeout => "Session has timed out.",
            PoolMessage::ErrConnectionTimeout => "Connection attempt has timed out (15 ms).", // PendingDsaRequest.TIMEOUT
        }
    }

    pub fn get_status_message(status: PoolStatus) -> &'static str {
        match status {
            PoolStatus::Warmup => "Warming up...",
            PoolStatus::Connecting => "Trying to connect...",
            PoolStatus::Mixing => "Mixing in progress...",
            PoolStatus::Finished => "Mixing Finished",
            PoolStatus::ErrNoMasternodesDetected => "No masternodes detected",
            PoolStatus::ErrMasternodeNotFound => "Can't find random Masternode",
            PoolStatus::ErrWalletLocked => "Wallet is locked",
            PoolStatus::ErrNotEnoughFunds => "Not enough funds",
            PoolStatus::ErrNoInputs => "Can't mix: no compatible inputs found!",
            PoolStatus::WarnNoMixingQueues => "Failed to find mixing queue to join",
            PoolStatus::WarnNoCompatibleMasternode => "No compatible Masternode found",
            _ => "",
        }
    }
        
    pub fn pool_min_participants(chain_type: &ChainType) -> u32 {
        match chain_type {
            ChainType::MainNet => 3,
            ChainType::TestNet => 2,
            ChainType::DevNet(_) => 2,
        }
    }

    pub fn pool_max_participants(chain_type: &ChainType) -> u32 {
        match chain_type {
            ChainType::MainNet => 20,
            ChainType::TestNet => 20,
            ChainType::DevNet(_) => 20,
        }
    }

    pub fn get_rounds_string(rounds: i32) -> &'static str {
        match rounds {
            -4 => "bad index",
            -3 => "collateral",
            -2 => "non-denominated",
            -1 => "no such tx",
            _ => "coinjoin",
        }
    }

    fn get_input_value_by_prevout_hash(&self, prevout_hash: UInt256, index: u32) -> Option<InputValue> {
        unsafe {
            let input_ptr = (self.get_input_value_by_prevout_hash)(boxed(prevout_hash.0), index, self.opaque_context);
            
            if input_ptr.is_null() {
                return None 
            } 

            let input_value: InputValue = std::ptr::read(input_ptr);
            (self.destroy_input_value)(input_ptr);
            Some(input_value)
        }
    }
}