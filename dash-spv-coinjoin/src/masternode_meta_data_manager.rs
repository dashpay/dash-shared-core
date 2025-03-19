use std::collections::HashMap;
use dashcore::hash_types::ProTxHash;
use crate::models::masternode_meta_info::MasternodeMetaInfo;

#[derive(Debug)]
pub struct MasternodeMetadataManager {
    meta_infos: HashMap<ProTxHash, MasternodeMetaInfo>,
    pub dsq_count: i64
}

impl MasternodeMetadataManager {
    pub fn new() -> MasternodeMetadataManager {
        Self {
            meta_infos: HashMap::new(),
            dsq_count: 0
        }
    }

    pub fn get_meta_info(&mut self, pro_tx_hash: ProTxHash, create: bool) -> Option<MasternodeMetaInfo> {
        if let Some(info) = self.meta_infos.get(&pro_tx_hash) {
            return Some(info.clone());
        }
        if !create {
            return None;
        }
        let info = MasternodeMetaInfo::new(pro_tx_hash);
        self.meta_infos.insert(pro_tx_hash, info.clone());
        Some(info)
    }

    pub fn get_dsq_threshold(&mut self, pro_tx_hash: ProTxHash, mn_count: u64) -> i64 {
        if let Some(meta_info) = self.get_meta_info(pro_tx_hash, true) {
            meta_info.last_dsq + (mn_count / 5) as i64
        } else {
            // return a threshold which is slightly above nDsqCount i.e. a no-go
            mn_count as i64 / 5
        }
    }

    pub fn allow_mixing(&mut self, pro_tx_hash: ProTxHash) {
        if let Some(mm) = self.meta_infos.get_mut(&pro_tx_hash) {
            self.dsq_count += 1;
            mm.last_dsq = self.dsq_count;
            mm.mixing_tx_count = 0;
            return;
        }

        let mut info = MasternodeMetaInfo::new(pro_tx_hash);
        self.dsq_count += 1;
        info.last_dsq = self.dsq_count;
        info.mixing_tx_count = 0;
        self.meta_infos.insert(pro_tx_hash, info);
    }
}