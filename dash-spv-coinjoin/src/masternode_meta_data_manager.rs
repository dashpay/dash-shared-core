use std::collections::HashMap;
use dash_spv_masternode_processor::crypto::UInt256;
use crate::models::masternode_meta_info::MasternodeMetaInfo;

#[derive(Debug)]
pub(crate) struct MasternodeMetadataManager {
    meta_infos: HashMap<UInt256, MasternodeMetaInfo>,
    pub dsq_count: i64
}

impl MasternodeMetadataManager {
    pub fn new() -> MasternodeMetadataManager {
        return Self {
            meta_infos: HashMap::new(),
            dsq_count: 0
        };
    }

    pub fn get_meta_info(&mut self, pro_tx_hash: UInt256, create: bool) -> Option<MasternodeMetaInfo> {
        if let Some(info) = self.meta_infos.get(&pro_tx_hash) {
            return Some(info.clone());
        }

        if !create {
            return None;
        }

        let info = MasternodeMetaInfo::new(pro_tx_hash);
        self.meta_infos.insert(pro_tx_hash, info.clone());

        return Some(info);
    }

    pub fn get_dsq_threshold(&mut self, pro_tx_hash: UInt256, mn_count: u64) -> i64 {
        if let Some(meta_info) = self.get_meta_info(pro_tx_hash, true) {
            return meta_info.last_dsq + (mn_count / 5) as i64;
        } else {
            // return a threshold which is slightly above nDsqCount i.e. a no-go
            return mn_count as i64 / 5;
        }
    }

    pub fn allow_mixing(&mut self, pro_tx_hash: UInt256) {
        if let Some(mut mm) = self.get_meta_info(pro_tx_hash, true) {
            self.dsq_count += 1;
            mm.last_dsq = self.dsq_count;
            mm.mixing_tx_count = 0;
        }
    }
}