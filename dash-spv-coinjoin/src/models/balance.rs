use std::fmt;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Balance {
    pub my_trusted: u64,           // Trusted, at depth=GetBalance.min_depth or more
    pub my_untrusted_pending: u64, // Untrusted, but in mempool (pending)
    pub my_immature: u64,          // Immature coinbases in the main chain
    pub watch_only_trusted: u64,
    pub watch_only_untrusted_pending: u64,
    pub watch_only_immature: u64,
    pub anonymized: u64,
    pub denominated_trusted: u64,
    pub denominated_untrusted_pending: u64
}

impl Balance {
    pub fn new() -> Self{
        Self {
            my_trusted: 0,
            my_untrusted_pending: 0,
            my_immature: 0,
            watch_only_trusted: 0,
            watch_only_untrusted_pending: 0,
            watch_only_immature: 0,
            anonymized: 0,
            denominated_trusted: 0,
            denominated_untrusted_pending: 0
        }
    }
}

impl fmt::Display for Balance {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[RUST] CoinJoin: Balance(\n[RUST] CoinJoin: myTrusted: {}\n[RUST] CoinJoin: myUntrustedPending: {}\n[RUST] CoinJoin: myImmature: {}\n[RUST] CoinJoin: watchOnlyTrusted: {}\n[RUST] CoinJoin: watchOnlyUntrustedPending: {}\n[RUST] CoinJoin: watchOnlyImmature: {}\n[RUST] CoinJoin: anonymized: {}\n[RUST] CoinJoin: denominatedTrusted: {}\n[RUST] CoinJoin: denominatedUntrustedPending: {}\n",
            self.my_trusted,
            self.my_untrusted_pending,
            self.my_immature,
            self.watch_only_trusted,
            self.watch_only_untrusted_pending,
            self.watch_only_immature,
            self.anonymized,
            self.denominated_trusted,
            self.denominated_untrusted_pending
        )
    }
}
