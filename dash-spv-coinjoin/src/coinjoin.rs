use std::collections::HashMap;
use std::ptr::null;

use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::chain::params::DUFFS;
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use dash_spv_masternode_processor::tx::transaction::Transaction;
use dash_spv_masternode_processor::util::script::ScriptType;
use ferment_interfaces::boxed;

use crate::callbacks::GetInputValueByPrevoutHash;
use crate::messages::pool_message::PoolMessage;
use crate::messages::pool_status::PoolStatus;
use crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use crate::constants::COINJOIN_ENTRY_MAX_SIZE;
use crate::models::InputValue;

#[repr(C)]
#[derive(Debug)]
// #[ferment_macro::export]
pub struct CoinJoin {
    pub opaque_context: *const std::ffi::c_void,
    // pub chain_type: ChainType,
    pub get_input_value_by_prevout_hash: GetInputValueByPrevoutHash,
    map_dstx: HashMap<UInt256, CoinJoinBroadcastTx>, // TODO: thread safety
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
    ) -> Self {
        Self {
            opaque_context: null(),
            // chain_type: ChainType::MainNet,
            get_input_value_by_prevout_hash,
            map_dstx: HashMap::new(),
        }
    }

    pub fn get_standard_denominations() -> &'static [u64] {
        &Self::STANDARD_DENOMINATIONS
    }

    pub fn get_smallest_denomination() -> u64 {
        Self::STANDARD_DENOMINATIONS[Self::STANDARD_DENOMINATIONS.len() - 1]
    }

    pub fn is_denominated_amount(n_input_amount: u64) -> bool {
        Self::amount_to_denomination(n_input_amount) > 0
    }

    pub fn is_valid_denomination(n_denom: i32) -> bool {
        Self::denomination_to_amount(n_denom) > 0
    }

    /// Return a bitshifted integer representing a denomination in STANDARD_DENOMINATIONS
    /// or 0 if none was found
    pub fn amount_to_denomination(n_input_amount: u64) -> i32 {
        for (i, &denom) in Self::STANDARD_DENOMINATIONS.iter().enumerate() {
            if n_input_amount == denom {
                return 1 << i;
            }
        }

        return 0;
    }

    /// # Returns
    /// - one of standard denominations from STANDARD_DENOMINATIONS based on the provided bitshifted integer
    /// - 0 for non-initialized sessions (nDenom = 0)
    /// - a value below 0 if an error occurred while converting from one to another
    pub fn denomination_to_amount(n_denom: i32) -> i64 {
        if n_denom == 0 {
            // not initialized
            return 0;
        }
    
        let n_max_denoms = Self::STANDARD_DENOMINATIONS.len();
    
        if n_denom >= (1 << n_max_denoms) || n_denom < 0 {
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

    pub fn denomination_to_string(n_denom: i32) -> String {
        match Self::denomination_to_amount(n_denom) {
            0 => "N/A".to_string(),
            -1 => "out-of-bounds".to_string(),
            -2 => "non-denom".to_string(),
            -3 => "to-amount-error".to_string(),
            n => format!("{}", n),
        }
    }

    // check to make sure the collateral provided by the client is valid
    pub fn is_collateral_valid(&self, tx_collateral: &Transaction, check_inputs: bool) -> bool {
        if tx_collateral.outputs.is_empty() {
            // TODO: logs
            // TODO: tx_hash.to_hex
            println!("coinjoin: Collateral invalid due to no outputs: {}", tx_collateral.tx_hash.unwrap_or_default());
            return false;
        }

        if tx_collateral.lock_time != 0 {
            println!("coinjoin: Collateral invalid due to lock time != 0: {}", tx_collateral.tx_hash.unwrap_or_default());
            return false;
        }
    
        let mut n_value_in: i64 = 0;
        let mut n_value_out: i64 = 0;
    
        for txout in &tx_collateral.outputs {
            n_value_out = n_value_out + txout.amount as i64;
    
            if txout.script_pub_key_type() != ScriptType::PayToPubkeyHash && !txout.is_script_unspendable() {
                println!("coinjoin: Invalid Script, txCollateral={}", tx_collateral.tx_hash().unwrap_or_default());
                return false;
            }
        }
    
        if check_inputs {
            for txin in &tx_collateral.inputs {
                let result = self.get_input_value_by_prevout_hash(txin.input_hash);
                
                if let Some(input_value) = result {
                    if !input_value.is_valid {
                       return false;
                    }

                    n_value_in = n_value_in + input_value.value as i64;
                } else {
                    println!("coinjoin: -- Unknown inputs in collateral transaction, txCollateral={}", tx_collateral.tx_hash().unwrap_or_default());
                    return false;
                }
            }

            if n_value_in - n_value_out < CoinJoin::get_collateral_amount() as i64 {
                println!("coinjoin: did not include enough fees in transaction: fees: {}, txCollateral={}", n_value_out - n_value_in, tx_collateral.tx_hash().unwrap_or_default());
                return false;
            }
        }
    
        true
    }

    pub fn get_collateral_amount() -> u64 { Self::get_smallest_denomination() / 10 }

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

    fn get_input_value_by_prevout_hash(&self, prevout_hash: UInt256) -> Option<InputValue> {
        unsafe { 
            let input_ptr = (self.get_input_value_by_prevout_hash)(boxed(prevout_hash.0), self.opaque_context);
            
            if !input_ptr.is_null() {
                let input_value: InputValue = std::ptr::read(input_ptr);
                Some(input_value)
            } else {
                None
            }
        }
    }
}