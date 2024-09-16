#[repr(C)]
pub struct CoinJoinDenominations {
    pub denoms: *const u64,
    pub length: usize,
}