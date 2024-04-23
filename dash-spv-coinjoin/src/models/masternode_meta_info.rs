use dash_spv_masternode_processor::crypto::UInt256;

#[derive(Debug, Clone)]
pub struct MasternodeMetaInfo {
    pub pro_tx_hash: UInt256,
    // the dsq count from the last dsq broadcast of this node
    pub last_dsq: i64,
    pub mixing_tx_count: i32
}

impl MasternodeMetaInfo {
    pub fn new(pro_tx_hash: UInt256) -> MasternodeMetaInfo {
        Self {
            pro_tx_hash,
            last_dsq: 0,
            mixing_tx_count: 0
        }
    }
}