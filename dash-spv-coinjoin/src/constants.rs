use dash_spv_masternode_processor::chain::params::{MAX_MONEY, DUFFS};

pub const COINJOIN_ENTRY_MAX_SIZE: u64 = 9;

pub const MIN_COINJOIN_SESSIONS: i32 = 1;
pub const MIN_COINJOIN_ROUNDS: i32 = 2;
pub const MIN_COINJOIN_AMOUNT: i32 = 2;
pub const MIN_COINJOIN_DENOMS_GOAL: i32 = 10;
pub const MIN_COINJOIN_DENOMS_HARDCAP: i32 = 10;
pub const MAX_COINJOIN_SESSIONS: i32 = 10;
pub const MAX_COINJOIN_ROUNDS: i32 = 16;
pub const MAX_COINJOIN_DENOMS_GOAL: i32 = 100000;
pub const MAX_COINJOIN_DENOMS_HARDCAP: i32 = 100000;
pub const MAX_COINJOIN_AMOUNT: u64 = MAX_MONEY / DUFFS;
pub const DEFAULT_COINJOIN_SESSIONS: i32 = 4;
pub const DEFAULT_COINJOIN_ROUNDS: i32 = 4;
pub const DEFAULT_COINJOIN_AMOUNT: i32 = 1000;
pub const DEFAULT_COINJOIN_DENOMS_GOAL: u32 = 50;
pub const DEFAULT_COINJOIN_DENOMS_HARDCAP: u32 = 300;

// How many new denom outputs to create before we consider the "goal" loop in CreateDenominated
// a final one and start creating an actual tx. Same limit applies for the "hard cap" part of the algo.
// NOTE: We do not allow txes larger than 100kB, so we have to limit the number of outputs here.
// We still want to create a lot of outputs though.
// Knowing that each CTxOut is ~35b big, 400 outputs should take 400 x ~35b = ~17.5kb.
// More than 500 outputs starts to make qt quite laggy.
// Additionally to need all 500 outputs (assuming a max per denom of 50) you'd need to be trying to
// create denominations for over 3000 dash!
pub const COINJOIN_DENOM_OUTPUTS_THRESHOLD: i32 = 500;

// Warn user if mixing in gui or try to create backup if mixing in daemon mode
// when we have only this many keys left
pub const COINJOIN_KEYS_THRESHOLD_WARNING: i32 = 100;
// Stop mixing completely, it's too dangerous to continue when we have only this many keys left
pub const COINJOIN_KEYS_THRESHOLD_STOP: i32 = 50;
// Pseudorandomly mix up to this many times in addition to base round count
pub const COINJOIN_RANDOM_ROUNDS: i32 = 3;

// If feePerKb is lower than this, Dash Core will treat it as if there were no fee.
pub const REFERENCE_DEFAULT_MIN_TX_FEE: u64 = 1000; // 0.01 mDASH

pub const COINJOIN_QUEUE_TIMEOUT: i64 = 30;