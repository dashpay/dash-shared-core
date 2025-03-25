use std::collections::HashSet;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};
use dashcore::blockdata::transaction::Transaction;
use dashcore::blockdata::transaction::txin::TxIn;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::hashes::Hash;
use logging::*;
use crate::coinjoin::CoinJoin;
use crate::messages::{coinjoin_entry::CoinJoinEntry, pool_state::PoolState, pool_status::PoolStatus, pool_message::PoolMessage};
use crate::models::valid_in_outs::ValidInOuts;

#[derive(Debug)]
#[ferment_macro::export]
pub struct CoinJoinBaseSession {
    pub entries: Vec<CoinJoinEntry>,
    pub final_mutable_transaction: Option<Transaction>,
    pub state: PoolState,
    pub status: PoolStatus,
    pub time_last_successful_step: u64,
    pub session_id: i32,
    pub session_denom: u32, // Users must submit a denom matching this,
}

impl CoinJoinBaseSession {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            final_mutable_transaction: None,
            state: PoolState::Idle,
            status: PoolStatus::Warmup,
            time_last_successful_step: 0,
            session_id: 0,
            session_denom: 0
        }
    }

    pub fn set_null(&mut self) {
        self.state = PoolState::Idle;
        self.session_id = 0;
        self.entries.clear();
        self.final_mutable_transaction = None;
        self.time_last_successful_step = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => { println!("Failed to get time since epoch"); 0 },
        }
    }

    pub fn is_valid_in_outs(&self, vin: &Vec<TxIn>, vout: &Vec<TxOut>) -> ValidInOuts {
        let mut set_scrip_pub_keys = HashSet::new();
        let mut result = ValidInOuts::new();
        
        if vin.len() != vout.len() {
            log_error!(target: "CoinJoin", "ERROR: inputs vs outputs size mismatch! {} vs {}", vin.len(), vout.len());
            result.message_id = PoolMessage::ErrSizeMismatch;
            result.consume_collateral = true;
            result.result = false;

            return result;
        }

        let mut check_tx_out = |tx_out: &TxOut| -> ValidInOuts {
            let denom = CoinJoin::amount_to_denomination(tx_out.value);
            let mut result = ValidInOuts::new();

            if denom != self.session_denom {
                log_error!(target: "CoinJoin", "ERROR: incompatible denom {} ({}) != sessionDenom {} ({})",
                    denom, CoinJoin::denomination_to_string(denom), self.session_denom, CoinJoin::denomination_to_string(self.session_denom));
                result.message_id = PoolMessage::ErrDenom;
                result.consume_collateral = true;
                result.result = false;

                return result;
            }

            let out_script = tx_out.script_pubkey.to_hex_string();
            // let hex = tx_out.script_pubkey.as_ref().unwrap_or(&vec![]).to_hex();

            if !tx_out.script_pubkey.is_p2pkh() {
                log_error!(target: "CoinJoin", "ERROR: invalid scriptPubKey={}", out_script);
                result.message_id = PoolMessage::ErrInvalidScript;
                result.consume_collateral = true;
                result.result = false;

                return result;
            }

            if !set_scrip_pub_keys.insert(out_script.clone()) {
                log_error!(target: "CoinJoin", "ERROR: already have this script! scriptPubKey={}", out_script);
                result.message_id = PoolMessage::ErrAlreadyHave;
                result.consume_collateral = true;
                result.result = false;

                return result;
            }

            // IsPayToPublicKeyHash() above already checks for scriptPubKey size,
            // no need to double-check, hence no usage of ERR_NON_STANDARD_PUBKEY
            result.result = true;

            return result;
        };

        // Note: here, Dash Core checks that the fee's are zero, but we cannot since we don't have access to all of the inputs

        for tx_out in vout {
            let output_result = &check_tx_out(&tx_out);

            if !output_result.result {
                result.result = false;
                return result;
            }
        }

        for tx_in in vin {
            if tx_in.previous_output.txid.as_byte_array().is_empty() {
                log_error!(target: "CoinJoin", "ERROR: invalid input! {:?}", tx_in);
                result.message_id = PoolMessage::ErrInvalidInput;
                result.consume_collateral = true;
                result.result = false;

                return result;
            }
        }

        result
    }

    pub fn get_state_string(&self) -> &'static str {
        match self.state {
            PoolState::Idle => "IDLE",
            PoolState::Queue => "QUEUE",
            PoolState::AcceptingEntries => "ACCEPTING_ENTRIES",
            PoolState::Signing => "SIGNING",
            PoolState::Error => "ERROR"
        }
    }
}
