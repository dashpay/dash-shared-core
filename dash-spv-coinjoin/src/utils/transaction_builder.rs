use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;
use tracing::{info, debug};
use logging::*;
use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::chain::params::TX_MIN_OUTPUT_AMOUNT;
use dash_spv_masternode_processor::chain::tx::protocol::TXIN_SEQUENCE;
use dash_spv_masternode_processor::consensus::Encodable;
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::ffi::ByteArray;
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use dash_spv_masternode_processor::util::data_append::DataAppend;

use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::constants::REFERENCE_DEFAULT_MIN_TX_FEE;
use crate::ffi::recepient::Recipient;
use crate::utils::coin_format::CoinFormat;
use crate::wallet_ex::WalletEx;
use crate::models::coin_control::CoinControl;
use crate::models::reserve_destination::ReserveDestination; 
use crate::models::transaction_builder_output::TransactionBuilderOutput;

pub struct TransactionBuilder {
    /// Wallet the transaction will be build for
    wallet_ex: Rc<RefCell<WalletEx>>,
    /// See CTransactionBuilder() for initialization
    coin_control: CoinControl,
    /// Dummy since we anyway use tallyItem's destination as change destination in coincontrol.
    /// Its a member just to make sure ReturnKey can be called in destructor just in case it gets generated/kept
    /// somewhere in CWallet code.
    dummy_reserve_destination: ReserveDestination,
    /// Contains all utxos available to generate this transactions. They are all from the same address.
    tally_item: CompactTallyItem,
    /// Contains the number of bytes required for a transaction with only the inputs of tallyItems, no outputs
    pub bytes_base: i32,
    /// Contains the number of bytes required to add one output
    bytes_output: i32,
    /// Call KeepKey for all keys in destructor if fKeepKeys is true, call ReturnKey for all key if its false.
    keep_keys: bool,
    /// Contains all outputs already added to the transaction
    pub outputs: Vec<TransactionBuilderOutput>,
    dry_run: bool
}

impl Drop for TransactionBuilder {
    fn drop(&mut self) {
        self.clear();
    }
}

impl<'a> TransactionBuilder {
    pub fn new(
        wallet_ex: Rc<RefCell<WalletEx>>, 
        chain_type: ChainType,
        tally_item: CompactTallyItem, 
        dry_run: bool
    ) -> Self {
        let mut coin_control = CoinControl::new();
        // Generate a feerate which will be used to consider if the remainder is dust and will go into fees or not
        coin_control.discard_fee_rate = REFERENCE_DEFAULT_MIN_TX_FEE;
        // Generate a feerate which will be used by calculations of this class and also by CWallet::CreateTransaction
        coin_control.fee_rate = REFERENCE_DEFAULT_MIN_TX_FEE;
        // Change always goes back to origin
        coin_control.dest_change = tally_item.tx_destination.clone();
        // Only allow tallyItems inputs for tx creation
        coin_control.allow_other_inputs = false;

        let mut dummy_tx = Transaction {
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            version: 0, 
            tx_hash: None,
            tx_type: TransactionType::Classic,
            payload_offset: 0,
            block_height: 0
        };

        // Select all tallyItem outputs in the coinControl so that CreateTransaction knows what to use
        for coin in &tally_item.input_coins {
            coin_control.select(coin.tx_outpoint.clone());
            let input = TransactionInput {
                input_hash: coin.tx_outpoint.hash,
                index: coin.tx_outpoint.index,
                script: None,
                signature: Some(Vec::new()),
                sequence: TXIN_SEQUENCE
            };
            dummy_tx.inputs.push(input);
        }

        let bytes_base = TransactionBuilder::calculate_maximum_signed_tx_size(wallet_ex.clone(), &mut dummy_tx);
        let bytes_output: i32 = TransactionBuilder::calculate_bytes_output(chain_type);

        let mut tx_builder = Self {
            wallet_ex: wallet_ex.clone(),
            coin_control,
            dummy_reserve_destination: ReserveDestination::new(wallet_ex),
            tally_item,
            bytes_base,
            bytes_output,
            keep_keys: false,
            outputs: Vec::new(),
            dry_run
        };
        tx_builder.clear();
        tx_builder
    }

    /// Check it would be possible to add a single output with the amount amount. Returns true if its possible and false if not.
    pub fn could_add_output(&self, amount_output: u64) -> bool {
        // Adding another output can change the serialized size of the vout size hence + GetSizeOfCompactSizeDiff()
        let bytes = self.get_bytes_total() + self.bytes_output + self.get_size_of_compact_size_diff(1);
        return TransactionBuilder::get_amount_left(self.get_amount_initial() as i64, (self.get_amount_used() + amount_output) as i64, self.get_fee(bytes as u64) as i64) >= 0;
    }

    /// Check if it's possible to add multiple outputs as vector of amounts. Returns true if its possible to add all of them and false if not.
    pub fn could_add_outputs(&self, vec_output_amounts: &[u64]) -> bool {
        let mut amount_additional = 0;
        let bytes_additional = self.bytes_output * vec_output_amounts.len() as i32;
        let vec_len = vec_output_amounts.len();

        for amount_output in vec_output_amounts {
            amount_additional += *amount_output;
        }
        // Adding other outputs can change the serialized size of the vout size hence + GetSizeOfCompactSizeDiff()
        let bytes = self.get_bytes_total() + bytes_additional + self.get_size_of_compact_size_diff(vec_len);
        return TransactionBuilder::get_amount_left(self.get_amount_initial() as i64, self.get_amount_used() as i64 + amount_additional as i64, self.get_fee(bytes as u64) as i64) >= 0;
    }

    /// Get amount we had available when we started
    pub fn get_amount_initial(&self) -> u64 {
        return self.tally_item.amount;
    }

    /// Helper to calculate static amount left by simply subtracting an used amount and a fee from a provided initial amount.
    pub fn get_amount_left(amount_initial: i64, amount_used: i64, fee: i64) -> i64{
        return amount_initial - amount_used - fee;
    }

    /// Get the amount currently left to add more outputs. Does respect fees.
    pub fn amount_left(&self) -> u64 {
        let initial = self.get_amount_initial();
        let used = self.get_amount_used();
        let fee = self.get_fee(self.get_bytes_total() as u64);

        return initial.saturating_sub(used).saturating_sub(fee);
    }

    /// Check if an amounts should be considered as dust
    pub fn is_dust(amount: u64) -> bool {
        return TX_MIN_OUTPUT_AMOUNT > amount;
    }

    /// Add an output with the amount. Returns a pointer to the output if it could be added and nullptr if not due to insufficient amount left.
    pub fn add_zero_output(&mut self) -> bool {
        return self.add_output(0)
    }

    pub fn add_output(&mut self, amount_output: u64) -> bool {
        if self.could_add_output(amount_output) {
            self.outputs.push(TransactionBuilderOutput::new(self.wallet_ex.clone(), amount_output as u64, self.dry_run));
            return true;
        }
        return false;
    }

    pub fn commit(&mut self, str_result: &mut String, is_denominating: bool, client_session_id: UInt256) -> bool {
        let vec_send: Vec<Recipient> = self.outputs
            .iter()
            .filter(|x| x.script.is_some())
            .map(|out| Recipient {
                script_pub_key: ByteArray::from(out.script.clone().unwrap()),
                amount: out.amount
            })
            .collect();

        log_debug!(target: "CoinJoin", "tx_builder.commit: {:?}", vec_send.iter().map(|f| f.amount).collect::<Vec<u64>>());

        if !self.wallet_ex.borrow().commit_transaction(&vec_send, self.coin_control.clone(), is_denominating, client_session_id) {
            log_debug!(target: "CoinJoin", "tx_builder.commit: Failed to commit transaction");
            str_result.push_str("Failed to commit transaction");
            return false;
        }

        log_debug!(target: "CoinJoin", "tx_builder.commit: Transaction committed");
        str_result.push_str("Transaction committed");
        self.keep_keys = true;
        return true;
    }

    fn calculate_maximum_signed_tx_size(wallet_ex: Rc<RefCell<WalletEx>>, tx: &mut Transaction) -> i32 {
        for input in tx.inputs.iter_mut() {
            match wallet_ex.borrow().get_wallet_transaction(input.input_hash) {
                Some(transaction) => {
                    assert!(input.index < transaction.outputs.len() as u32, "Index out of bounds");
                    input.script = transaction.outputs[input.index as usize].script.clone();
                },
                None => {
                    // Cannot estimate size without knowing the input details
                    return -1;
                }
            }
        }

        if let Some(signed_tx) = wallet_ex.borrow().sign_transaction(&tx, false) {
            return signed_tx.to_data().len() as i32;
        }

        log_info!(target: "CoinJoin", "TxBuilder: Could not sign transaction");
        return -1;
    }

    fn calculate_bytes_output(chain_type: ChainType) -> i32 {
        let script_map = chain_type.script_map();
        let pub_key = Vec::<u8>::script_pub_key_for_address(&TransactionBuilder::get_dummy_address(chain_type), &script_map);
        let tx_output = TransactionOutput { amount: 0, script: Some(pub_key), address: None };
        let mut buffer = Vec::new();
        tx_output.consensus_encode(&mut buffer).unwrap();
        
        return buffer.len() as i32;
    }

    fn get_dummy_address(chain_type: ChainType) -> String {
        return if chain_type == ChainType::MainNet { "XqQHMfqiEbmswPk7Ruhfq3WKrgANDunDgG".to_string() } else { "yVkt3e49pAj11jSj4HAnzVAWmy4VD1MwZd".to_string() };
    }

    fn get_bytes_total(&self) -> i32 {
        return self.bytes_base + self.outputs.len() as i32 * self.bytes_output + self.get_size_of_compact_size_diff(self.outputs.len());
    }
    
    fn get_size_of_compact_size_diff(&self, add: usize) -> i32 {
        let size = self.outputs.len();

        return self.get_compact_size_diff(size, size + add);
    }

    fn get_compact_size_diff(&self, old_size: usize, new_size: usize) -> i32 {
        let mut buffer = Vec::new();
        let old_var_int_size = (old_size as i32).consensus_encode(&mut buffer).unwrap() as i32;
        let new_var_int_size = (new_size as i32).consensus_encode(&mut buffer).unwrap() as i32;

        return old_var_int_size - new_var_int_size;
    }

    fn get_amount_used(&self) -> u64 {
        let mut amount = 0;
        for output in &self.outputs {
            amount += output.amount;
        }
        return amount;
    }

    /// Get fees based on the number of bytes and the feerate set in CoinControl.
    /// NOTE: To get the total transaction fee this should only be called once with the total number of bytes for the transaction to avoid
    /// calling CFeeRate::GetFee multiple times with subtotals as this may add rounding errors with each further call.
    fn get_fee(&self, bytes: u64) -> u64 {
        let mut fee_calc = self.coin_control.fee_rate * bytes;
        let required_fee = REFERENCE_DEFAULT_MIN_TX_FEE * bytes / 1000;
        
        if required_fee > fee_calc {
            fee_calc = required_fee;
        }
        if fee_calc > REFERENCE_DEFAULT_MIN_TX_FEE * 10 {
            fee_calc = REFERENCE_DEFAULT_MIN_TX_FEE;
        }

        return fee_calc;
    }

    /// Clear the output vector and keep/return the included keys depending on the value of fKeepKeys
    pub fn clear(&mut self) {
        println!("[RUST] CoinJoin TxBuilder: clear");

        let mut vec_outputs_tmp = self.outputs.clone();
        self.outputs.clear();

        for output in &mut vec_outputs_tmp {
            if self.keep_keys {
                output.keep_key();
            } else {
                output.return_key();
            }
        }
        
        // Always return this key
        self.dummy_reserve_destination.return_destination();
    }
}

impl fmt::Display for TransactionBuilder {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TransactionBuilder(Amount initial: {}, Amount left: {}, Bytes base: {}, Bytes output: {}, Bytes total: {}, Amount used: {}, Outputs: {}, Fee rate: {}, Discard fee rate: {}, Fee: {})",
            self.get_amount_initial().to_friendly_string(),
            self.amount_left().to_friendly_string(),
            self.bytes_base,
            self.bytes_output,
            self.get_bytes_total(),
            self.get_amount_initial().to_friendly_string(),
            self.outputs.len(),
            self.coin_control.fee_rate.to_friendly_string(),
            self.coin_control.discard_fee_rate.to_friendly_string(),
            self.get_fee(self.get_bytes_total() as u64).to_friendly_string()
        )
    }
}
