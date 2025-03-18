use std::net::SocketAddr;
use std::time::{SystemTime, Duration};
use crate::messages::CoinJoinAcceptMessage;

#[derive(Debug)]
pub(crate) struct PendingDsaRequest {
    pub addr: SocketAddr,
    pub dsa: CoinJoinAcceptMessage,
    time_created: SystemTime,
}

const TIMEOUT: Duration = Duration::from_secs(15);

impl PendingDsaRequest {
    pub fn new(addr: SocketAddr, dsa: CoinJoinAcceptMessage) -> Self {
        Self { addr, dsa, time_created: SystemTime::now() }
    }

    pub fn is_expired(&self) -> bool {
        self.time_created.elapsed().unwrap() > TIMEOUT
    }
}

impl std::fmt::Display for PendingDsaRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PendingDsaRequest {{ addr: {}, dsa: {}, n_time_created: {:?} }}",
               self.addr, self.dsa, self.time_created)
    }
}
