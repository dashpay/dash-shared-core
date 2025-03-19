use dashcore::hash_types::ProTxHash;

#[derive(Debug, Clone)]
#[ferment_macro::export]
pub struct MasternodeMetaInfo {
    pub pro_tx_hash: ProTxHash,
    // the dsq count from the last dsq broadcast of this node
    pub last_dsq: i64,
    pub mixing_tx_count: i32
}

impl MasternodeMetaInfo {
    pub fn new(pro_tx_hash: ProTxHash) -> MasternodeMetaInfo {
        Self {
            pro_tx_hash,
            last_dsq: 0,
            mixing_tx_count: 0
        }
    }
}