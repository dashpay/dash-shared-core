use std::cell::RefCell;
use std::fmt;
use std::rc::Rc;

use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::chain::params::TX_MIN_OUTPUT_AMOUNT;
use dash_spv_masternode_processor::consensus::Encodable;
use dash_spv_masternode_processor::ffi::boxer::boxed;
use dash_spv_masternode_processor::ffi::to::ToFFI;
use dash_spv_masternode_processor::hashes::hex::ToHex;
use dash_spv_masternode_processor::tx::{Transaction, TransactionInput, TransactionOutput, TransactionType};
use dash_spv_masternode_processor::util::data_append::DataAppend;

use crate::coin_selection::compact_tally_item::CompactTallyItem;
use crate::constants::REFERENCE_DEFAULT_MIN_TX_FEE;
use crate::ffi::callbacks::SignTransaction;
use crate::models::recepient::Recipient;
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
    vec_outputs: Vec<TransactionBuilderOutput>,
    dry_run: bool,
    chain_type: ChainType,
    sign_transaction: SignTransaction,
    opaque_context: *const std::ffi::c_void,
}

impl<'a> TransactionBuilder {
    pub fn new(
        wallet_ex: Rc<RefCell<WalletEx>>, 
        sign_transaction: SignTransaction,
        dry_run: bool,
        chain_type: ChainType,
        opaque_context: *const std::ffi::c_void
    ) -> Self {
        Self {
            wallet_ex: wallet_ex.clone(),
            coin_control: CoinControl::new(),
            dummy_reserve_destination: ReserveDestination::new(wallet_ex),
            tally_item: CompactTallyItem::new(None),
            bytes_base: 0,
            bytes_output: 0,
            keep_keys: false,
            vec_outputs: Vec::new(),
            dry_run,
            chain_type,
            sign_transaction,
            opaque_context
        }
    }

    pub fn init(&mut self, tally_item: CompactTallyItem) {
        self.clear();

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
                signature: None,
                sequence: 0
            };
            dummy_tx.inputs.push(input);
        }

        self.coin_control = coin_control;
        self.tally_item = tally_item;
        self.calculate_maximum_signed_tx_size(dummy_tx);
        self.calculate_bytes_output();
    }

    /// Check it would be possible to add a single output with the amount amount. Returns true if its possible and false if not.
    pub fn could_add_output(&self, amount_output: i64) -> bool {
        if amount_output < 0 {
            return false;
        }
        
        // Adding another output can change the serialized size of the vout size hence + GetSizeOfCompactSizeDiff()
        let bytes = self.get_bytes_total() + self.bytes_output + self.get_size_of_compact_size_diff(1);
        return TransactionBuilder::get_amount_left(self.get_amount_initial() as i64, self.get_amount_used() as i64 + amount_output, self.get_fee(bytes as u64) as i64) >= 0;
    }

    /// Check if it's possible to add multiple outputs as vector of amounts. Returns true if its possible to add all of them and false if not.
    pub fn could_add_outputs(&self, vec_output_amounts: Vec<i64>) -> bool {
        let mut amount_additional = 0;
        let bytes_additional = self.bytes_output * vec_output_amounts.len() as i32;
        let vec_len = vec_output_amounts.len();

        for amount_output in vec_output_amounts {
            if amount_output < 0 {
                return false;
            }
            amount_additional += amount_output;
        }
        // Adding other outputs can change the serialized size of the vout size hence + GetSizeOfCompactSizeDiff()
        let bytes = self.get_bytes_total() + bytes_additional + self.get_size_of_compact_size_diff(vec_len);
        return TransactionBuilder::get_amount_left(self.get_amount_initial() as i64, self.get_amount_used() as i64 + amount_additional, self.get_fee(bytes as u64) as i64) >= 0;
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
        return self.get_amount_initial() - self.get_amount_used() - self.get_fee(self.get_bytes_total() as u64);
    }

    /// Check if an amounts should be considered as dust
    pub fn is_dust(amount: u64) -> bool {
        return TX_MIN_OUTPUT_AMOUNT > amount;
    }

    /// Add an output with the amount. Returns a pointer to the output if it could be added and nullptr if not due to insufficient amount left.
    pub fn add_output(&mut self, amount_output: i64) -> Option<&TransactionBuilderOutput> {
        if self.could_add_output(amount_output) {
            self.vec_outputs.push(TransactionBuilderOutput::new(self.wallet_ex.clone(), amount_output as u64, self.dry_run));
            return self.vec_outputs.last();
        }
        return None;
    }

    pub fn commit(&mut self, str_result: &String) -> bool {
        let vec_send: Vec<Recipient> = self.vec_outputs
            .iter()
            .map(|out| Recipient {
                script_pub_key: out.script.clone(), 
                amount: out.amount,
                subtract_fee_from_amount: false,
            })
            .collect();

        // TODO: commit transaction
        self.keep_keys = true;
        return true;
    }

    fn calculate_maximum_signed_tx_size(&mut self, mut tx: Transaction) {
        println!("[RUST] CoinJoin: calculate_maximum_signed_tx_size: tx: {:?}", tx);
        for input in tx.inputs.iter_mut() {
            match self.wallet_ex.borrow().get_wallet_transaction(input.input_hash) {
                Some(transaction) => {
                    assert!(input.index < transaction.outputs.len() as u32, "Index out of bounds");
                    input.script = transaction.outputs[input.index as usize].script.clone();
                },
                None => {
                    // Cannot estimate size without knowing the input details
                    self.bytes_base = -1;
                    return;
                }
            }
        }

        unsafe { (self.sign_transaction)(boxed(tx.encode()), self.opaque_context); }
    }

    fn calculate_bytes_output(&mut self) {
        let script_map = self.chain_type.script_map();
        let pub_key = Vec::<u8>::script_pub_key_for_address(self.get_dummy_address(), &script_map);
        let tx_output = TransactionOutput { amount: 0, script: Some(pub_key), address: None };
        let mut buffer = Vec::new();
        tx_output.consensus_encode(&mut buffer).unwrap();
        self.bytes_output = buffer.len() as i32;
    }

    fn get_dummy_address(&self) -> &str {
        return if self.chain_type == ChainType::MainNet { "XqQHMfqiEbmswPk7Ruhfq3WKrgANDunDgG" } else { "yVkt3e49pAj11jSj4HAnzVAWmy4VD1MwZd" };
    }

    fn get_bytes_total(&self) -> i32 {
        return self.bytes_base + self.vec_outputs.len() as i32 * self.bytes_output + self.get_size_of_compact_size_diff(self.vec_outputs.len());
    }
    
    fn get_size_of_compact_size_diff(&self, add: usize) -> i32 {
        let size = self.vec_outputs.len();

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
        for output in &self.vec_outputs {
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
    fn clear(&mut self) {
        let mut vec_outputs_tmp = self.vec_outputs.clone();
        self.vec_outputs.clear();

        for output in &mut vec_outputs_tmp {
            if self.keep_keys {
                output.keep_key();
            } else {
                output.return_key();
            }
        }

        if let Some(address) = self.dummy_reserve_destination.address.clone() {
            println!("returning: {}", address.to_hex());
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
            self.vec_outputs.len(),
            self.coin_control.fee_rate.to_friendly_string(),
            self.coin_control.discard_fee_rate.to_friendly_string(),
            self.get_fee(self.get_bytes_total() as u64).to_friendly_string()
        )
    }
}
