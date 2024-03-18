use std::collections::HashMap;
use dash_spv_masternode_processor::crypto::UInt256;
use crate::models::masternode_meta_info::MasternodeMetaInfo;

pub(crate) struct MasternodeMetadataManager {
    meta_infos: HashMap<UInt256, MasternodeMetaInfo>
}

impl MasternodeMetadataManager {
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
}