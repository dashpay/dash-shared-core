#[repr(C)]
#[derive(Debug)]
pub struct CoinJoinClientOptions {
    pub enable_coinjoin: bool,
    pub coinjoin_amount: u64,
    pub coinjoin_sessions: i32, // TODO: Atomic?
    pub coinjoin_rounds: i32,
    pub coinjoin_random_rounds: i32,
    pub coinjoin_denoms_goal: i32,
    pub coinjoin_denoms_hardcap: i32,
    pub coinjoin_multi_session: bool
}