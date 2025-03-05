use dashcore::{BlockHash, ProTxHash};
use dashcore::sml::masternode_list::MasternodeList;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use crate::processing::MasternodeProcessor;

#[ferment_macro::export]
impl MasternodeProcessor {
    pub fn current_masternode_list(&self) -> Option<MasternodeList> {
        self.engine.latest_masternode_list().cloned()
    }

    pub fn has_current_masternode_list(&self) -> bool {
        self.engine.latest_masternode_list().is_some()
    }

    pub fn current_masternode_list_masternode_with_pro_reg_tx_hash(&self, hash: &ProTxHash) -> Option<QualifiedMasternodeListEntry> {
        let list = self.current_masternode_list();
        list.and_then(|list| list.masternode_for(hash).cloned())
    }
    pub fn current_masternode_list_masternode_count(&self) -> usize {
        let list = self.current_masternode_list();
        list.map(|list| list.masternode_count())
            .unwrap_or_default()
    }
    pub fn current_masternode_list_quorum_count(&self) -> usize {
        let list = self.current_masternode_list();
        list.map(|list| list.quorums_count() as usize)
            .unwrap_or_default()
    }

    pub fn masternode_list_for_block_hash(&self, block_hash: &BlockHash) -> Option<&MasternodeList> {
        self.engine.masternode_list_for_block_hash(block_hash)
    }
    // pub fn masternode_list_before_block_hash(&self, block_hash: &BlockHash) -> Option<MasternodeList> {
    //     let block_height = self.height_for_block_hash(block_hash);
    //     let mut closest_masternode_list = self.cache.read_mn_lists(|lock| {
    //         let mut min_distance = u32::MAX;
    //         let mut closest_masternode_list = None;
    //         for (block_hash_data, list) in lock.iter() {
    //             let masternode_list_block_height = self.height_for_block_hash(block_hash_data.clone());
    //             if block_height <= masternode_list_block_height {
    //                 continue;
    //             }
    //             let distance = block_height - masternode_list_block_height;
    //             if distance < min_distance {
    //                 min_distance = distance;
    //                 closest_masternode_list = Some(list.clone());
    //             }
    //         }
    //         closest_masternode_list
    //     });
    //     if self.provider.chain_type().is_mainnet() {
    //         if let Some(ref mut closest_masternode_list) = closest_masternode_list {
    //             if closest_masternode_list.known_height == 0 || closest_masternode_list.known_height == u32::MAX {
    //                 self.cache.write_mn_lists(|lock| {
    //                     if let Some(list) = lock.get_mut(&closest_masternode_list.block_hash) {
    //                         list.known_height = block_height;
    //                         closest_masternode_list.known_height = block_height;
    //                     }
    //                 })
    //             }
    //             if closest_masternode_list.known_height < CHAIN_LOCK_ACTIVATION_HEIGHT && block_height >= CHAIN_LOCK_ACTIVATION_HEIGHT {
    //                 return None; // special main net case
    //             }
    //         }
    //     }
    //     closest_masternode_list
    // }
}