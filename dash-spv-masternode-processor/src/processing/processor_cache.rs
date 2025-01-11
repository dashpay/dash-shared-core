use std::cmp;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use hashes::hex::ToHex;
use indexmap::IndexSet;
use dash_spv_crypto::llmq::LLMQEntry;
use dash_spv_crypto::network::LLMQType;
use crate::models::{llmq_indexed_hash::LLMQIndexedHash, masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use crate::models::sync_state::SyncState;
use crate::processing::MasternodeProcessor;

#[derive(Clone, Default)]
#[ferment_macro::export]
pub struct RetrievalQueue {
    pub queue: IndexSet<[u8; 32]>,
    pub max_amount: usize,
}

impl RetrievalQueue {
    pub fn has_latest_block_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        self.queue.last().map(|last| block_hash.eq(last)).unwrap_or(false)
    }
    pub fn first(&self) -> Option<[u8; 32]> {
        self.queue.first().cloned()
    }

    pub fn add(&mut self, block_hash: [u8; 32], processor: &MasternodeProcessor) {
        self.queue.insert(block_hash);
        self.update_retrieval_queue(processor);
    }
    pub fn update_retrieval_queue(&mut self, processor: &MasternodeProcessor) {
        let current_count = self.queue.len();
        self.max_amount = cmp::max(self.max_amount, current_count);
        self.queue.sort_by(|hash1, hash2| {
            let h1 = processor.height_for_block_hash(*hash1);
            let h2 = processor.height_for_block_hash(*hash2);
            h1.cmp(&h2)
        });
        processor.provider.notify_sync_state(SyncState::queue(self.queue.len(), self.max_amount));
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.max_amount = 0;
    }
}

#[derive(Default)]
#[ferment_macro::opaque]
pub struct MasternodeProcessorCache {
    pub llmq_members: Arc<RwLock<BTreeMap<LLMQType, BTreeMap<[u8; 32], Vec<MasternodeEntry>>>>>,
    pub llmq_indexed_members: Arc<RwLock<BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>>>,
    pub mn_list_stubs: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub llmq_snapshots: Arc<RwLock<BTreeMap<[u8; 32], LLMQSnapshot>>>,
    pub cl_signatures: Arc<RwLock<BTreeMap<[u8; 32], [u8; 96]>>>,
    pub needed_masternode_lists: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub list_awaiting_quorum_validation: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub list_needing_quorum_validation: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub cached_block_hash_heights: Arc<RwLock<BTreeMap<[u8; 32], u32>>>,
    pub active_quorums: Arc<RwLock<HashSet<LLMQEntry>>>,
    //last by height, not by time queried
    pub last_queried_block_hash: Arc<RwLock<[u8; 32]>>,

    pub mn_lists: Arc<RwLock<BTreeMap<[u8; 32], Arc<MasternodeList>>>>,
    pub last_qr_list_at_tip: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_qr_list_at_h: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_qr_list_at_h_c: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_qr_list_at_h_2c: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_qr_list_at_h_3c: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_qr_list_at_h_4c: Arc<RwLock<Option<Arc<MasternodeList>>>>,
    pub last_mn_list: Arc<RwLock<Option<Arc<MasternodeList>>>>,

    pub mn_list_retrieval_queue: Arc<RwLock<RetrievalQueue>>,
    pub qr_info_retrieval_queue: Arc<RwLock<RetrievalQueue>>,
}

impl std::fmt::Debug for MasternodeProcessorCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MasternodeProcessorCache")
            .field("llmq_members", &self.llmq_members)
            .field("llmq_indexed_members", &self.llmq_indexed_members)
            .field("llmq_snapshots", &self.llmq_snapshots)
            .field("mn_lists", &self.mn_lists)
            .field("cl_signatures", &self.cl_signatures)
            .field("needed_masternode_lists", &self.needed_masternode_lists)
            .field("lists_awaiting_quorum_validation", &self.list_awaiting_quorum_validation)
            .finish()
    }
}

impl MasternodeProcessorCache {
    pub fn get_quorum_members(
        &self,
        r#type: LLMQType,
        block_hash: [u8; 32],
    ) -> Option<Vec<MasternodeEntry>> {
        let lock = self.llmq_members.read().unwrap();
        let map_by_type_opt = lock.get(&r#type);
        let mut maybe_members = None;
        if let Some(members) = map_by_type_opt.as_ref()?.get(&block_hash) {
            maybe_members = Some(members.clone());
        }
        drop(lock);
        maybe_members
    }

    pub fn remove_quorum_members(&self, block_hash: &[u8; 32]) {
        let mut llmq_members_lock = self.llmq_members.write().unwrap();
        let mut llmq_indexed_members_lock = self.llmq_indexed_members.write().unwrap();
        llmq_members_lock.iter_mut().for_each(|(llmq_type, map)| {
            map.remove(block_hash);
        });
        drop(llmq_members_lock);
        llmq_indexed_members_lock.iter_mut().for_each(|(llmq_type, map)| {
            let empties = map
                .iter()
                .filter_map(|(k, _)| k.hash.eq(block_hash).then_some(k.clone()))
                .collect::<Vec<_>>();
            empties.iter().for_each(|h| {
                map.remove(h);
            });
        });
        drop(llmq_indexed_members_lock);
    }

}
#[ferment_macro::export]
impl MasternodeProcessorCache {
    pub fn clear(&self) {
        self.clear_current_lists();
        let mut lock = self.llmq_members.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.llmq_indexed_members.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.mn_lists.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.mn_list_stubs.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.llmq_snapshots.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.cl_signatures.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.needed_masternode_lists.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.cached_block_hash_heights.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.active_quorums.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.last_queried_block_hash.write().unwrap();
        *lock = [0u8; 32];
        drop(lock);
        let mut lock = self.mn_list_retrieval_queue.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.qr_info_retrieval_queue.write().unwrap();
        lock.clear();
        drop(lock);
    }
    pub fn clear_current_lists(&self) {
        let mut lock = self.last_qr_list_at_tip.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_qr_list_at_h.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_qr_list_at_h_c.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_qr_list_at_h_2c.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_qr_list_at_h_3c.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_qr_list_at_h_4c.write().unwrap();
        *lock = None;
        drop(lock);
        let mut lock = self.last_mn_list.write().unwrap();
        *lock = None;
        drop(lock);
    }

    pub fn masternode_list_loaded(&self, block_hash: [u8; 32], list: Arc<MasternodeList>) -> usize {
        let mut stubs_lock = self.mn_list_stubs.write().unwrap();
        stubs_lock.remove(&block_hash);
        drop(stubs_lock);
        let mut lists_lock = self.mn_lists.write().unwrap();
        lists_lock.insert(block_hash, list);
        let count = lists_lock.len();
        drop(lists_lock);
        println!("[CACHE] masternode_list_loaded: {} {}", block_hash.to_hex(), count);
        count
    }


    pub fn maybe_snapshot(&self, block_hash: [u8; 32]) -> Option<LLMQSnapshot> {
        let lock = self.llmq_snapshots.read().unwrap();
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }
    pub fn add_snapshot(&self, block_hash: [u8; 32], snapshot: LLMQSnapshot) {
        let mut lock = self.llmq_snapshots.write().unwrap();
        lock.insert(block_hash, snapshot);
        println!("[CACHE] snapshot added: {}", block_hash.to_hex());
        drop(lock);
    }
    pub fn remove_snapshot(&self, block_hash: &[u8; 32]) {
        let mut lock = self.llmq_snapshots.write().unwrap();
        lock.remove(block_hash);
        println!("[CACHE] snapshot removed: {}", block_hash.to_hex());
        drop(lock);
    }
    pub fn add_cl_signature(&self, block_hash: [u8; 32], cl_signature: [u8; 96]) {
        let mut lock = self.cl_signatures.write().unwrap();
        lock.insert(block_hash, cl_signature);
        //println!("[CACHE] clsig added: {} {}", block_hash.to_hex(), cl_signature.to_hex());
        drop(lock);
    }
    pub fn maybe_cl_signature(&self, block_hash: [u8; 32]) -> Option<[u8; 96]> {
        let lock = self.cl_signatures.read().unwrap();
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }

    pub fn remove_from_awaiting_quorum_validation_list(&self, block_hash: [u8; 32]) {
        let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
        println!("[CACHE] remove_from_awaiting_quorum_validation_list: {}", block_hash.to_hex());
        lock.remove(&block_hash);
        drop(lock);
    }
    pub fn has_in_awaiting_quorum_validation_list(&self, block_hash: [u8; 32]) -> bool {
        let lock = self.list_awaiting_quorum_validation.read().unwrap();
        let result = lock.contains(&block_hash);
        println!("[CACHE] has_in_awaiting_quorum_validation_list: {} = {result}", block_hash.to_hex());
        drop(lock);
        result
    }
    pub fn add_to_awaiting_quorum_validation_list(&self, hash: [u8; 32]) {
        let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
        println!("[CACHE] add_to_awaiting_quorum_validation_list: {}", hash.to_hex());
        lock.insert(hash);
        drop(lock);
    }

    pub fn add_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        println!("[CACHE] add_block_hash_for_list_needing_quorums_validated: {}", block_hash.to_hex());
        lock.insert(block_hash);
        drop(lock);
    }
    pub fn remove_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        println!("[CACHE] remove_block_hash_for_list_needing_quorums_validated: {}", block_hash.to_hex());
        lock.remove(&block_hash);
        drop(lock);
    }

    pub fn has_list_at_block_hash_needing_quorums_validated(&self, block_hash: [u8; 32]) -> bool {
        let lock = self.list_needing_quorum_validation.read().unwrap();
        let result = lock.contains(&block_hash);
        println!("[CACHE] has_list_at_block_hash_needing_quorums_validated: {}", block_hash.to_hex());
        drop(lock);
        result
    }

    pub fn add_masternode_list(&self, block_hash: [u8; 32], list: Arc<MasternodeList>) {
        let mut lock = self.mn_lists.write().unwrap();
        println!("[CACHE] add_masternode_list: {}", block_hash.to_hex());
        lock.insert(block_hash, list);
        drop(lock);
    }

    pub fn masternode_list_by_block_hash(&self, block_hash: [u8; 32]) -> Option<Arc<MasternodeList>> {
        let lock = self.mn_lists.read().unwrap();
        let result = lock.get(&block_hash);
        println!("[CACHE] masternode_list_by_block_hash: {}: {}", block_hash.to_hex(), result.as_ref().map(|b| b.known_height.to_string()).unwrap_or("None".to_string()));
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }
    pub fn remove_masternode_list(&self, block_hash: [u8; 32]) {
        let mut lock = self.mn_lists.write().unwrap();
        println!("[CACHE] remove_masternode_list: {}", block_hash.to_hex());
        lock.remove(&block_hash);
        drop(lock);
    }
    pub fn remove_masternode_lists_before_height(&self, height: u32) {
        let mut lock = self.mn_lists.write().unwrap();
        println!("[CACHE] remove_masternode_lists_before_height: {}", height);
        lock.retain(|_, value| value.known_height >= height);
        drop(lock);
    }

    pub fn contains_block_hash_needing_masternode_list(&self, block_hash: [u8; 32]) -> bool {
        let lock = self.needed_masternode_lists.read().unwrap();
        let result = lock.iter().any(|h| block_hash.eq(h));
        println!("[CACHE] contains_block_hash_needing_masternode_list: {} = {result}", block_hash.to_hex());
        drop(lock);
        result
    }
    pub fn has_block_hashes_needing_masternode_list(&self) -> bool {
        let lock = self.needed_masternode_lists.read().unwrap();
        println!("[CACHE] has_block_hashes_needing_masternode_list: {}", lock.is_empty());
        let result = !lock.is_empty();
        drop(lock);
        result
    }
    pub fn all_needed_masternode_list(&self) -> HashSet<[u8; 32]> {
        let b_lock = self.cached_block_hash_heights.read().unwrap();
        let lock = self.needed_masternode_lists.read().unwrap();
        println!("[CACHE] all_needed_masternode_list: {}", lock.iter().fold(String::new(), |mut acc, h| {
            acc.push_str(format!("\t{}:{},\n", b_lock.get(h).unwrap_or(&u32::MAX), h.to_hex()).as_str());
            acc
        }));
        let result = lock.clone();
        drop(b_lock);
        drop(lock);
        result
    }

    pub fn add_needed_masternode_lists(&self, lists: HashSet<[u8; 32]>) {
        let mut needed_lock = self.needed_masternode_lists.write().unwrap();
        needed_lock.extend(lists);
        drop(needed_lock);
    }

    pub fn clear_needed_masternode_lists(&self) {
        let mut lock = self.needed_masternode_lists.write().unwrap();
        lock.clear();
        drop(lock);
    }

    pub fn recent_masternode_lists(&self) -> Vec<Arc<MasternodeList>> {
        let lock = self.mn_lists.read().unwrap();
        let mut sorted = Vec::from_iter(lock.values().cloned());
        sorted.sort_by_key(|list| list.known_height);
        println!("[CACHE] recent_masternode_lists: {}", sorted.iter().fold(String::new(), |mut acc, h| {
            acc.push_str(format!("{}, ", h.known_height).as_str());
            acc
        }));
        drop(lock);
        sorted
    }

    pub fn known_masternode_lists_block_hashes(&self) -> HashSet<[u8; 32]> {
        let lists = self.mn_lists.read().unwrap();
        let stubs = self.mn_list_stubs.read().unwrap();
        let mut set = HashSet::<[u8; 32]>::from_iter(lists.keys().cloned());
        set.extend(stubs.iter().cloned());
        // println!("[CACHE] known_masternode_lists_block_hashes: {}", set.iter().fold(String::new(), |mut acc, h| {
        //     acc.push_str(format!("{}, ", h.to_hex()).as_str());
        //     acc
        // }));
        drop(lists);
        drop(stubs);
        set
    }
    pub fn known_masternode_lists_count(&self) -> usize {
        let lists = self.mn_lists.read().unwrap();
        let stubs = self.mn_list_stubs.read().unwrap();
        // let lists_d = lists.iter().fold(String::new(), |mut acc, (hash, list)| {
        //     acc.push_str(format!("{}:{},\n\t", list.known_height, hash.to_hex()).as_str());
        //     acc
        // });
        // let stubs_d = stubs.format();
        let mut set = HashSet::<&[u8; 32]>::from_iter(lists.keys());
        set.extend(stubs.iter());
        println!("[CACHE] known_masternode_lists_count: {}", set.len());
        let result = set.len();
        drop(lists);
        drop(stubs);
        result
    }

    pub fn stored_masternode_lists_count(&self) -> usize {
        let lists = self.mn_lists.read().unwrap();
        println!("[CACHE] stored_masternode_lists_count: {}", lists.len());
        let result = lists.len();
        drop(lists);
        result
    }

    pub fn has_masternode_list_at(&self, block_hash: [u8; 32]) -> bool {
        let lists_lock = self.mn_lists.read().unwrap();
        let has_list = lists_lock.contains_key(&block_hash);
        drop(lists_lock);
        if has_list {
            println!("[CACHE] has_masternode_list_at: {}: YES (LIST)", block_hash.to_hex());
            return true
        }
        let stubs_lock = self.mn_list_stubs.read().unwrap();
        let has_stub = stubs_lock.contains(&block_hash);
        drop(stubs_lock);
        println!("[CACHE] has_masternode_list_at: {}: {}", block_hash.to_hex(), if has_stub { "YES (STUB)" } else { "NO" });
        has_stub
    }

    pub fn add_stub_for_masternode_list(&self, block_hash: [u8; 32]) {
        let mut lock = self.mn_list_stubs.write().unwrap();
        println!("[CACHE] add_stub_for_masternode_list: {}", block_hash.to_hex());
        lock.insert(block_hash);
        drop(lock);
    }

    pub fn has_stub_for_masternode_list(&self, block_hash: [u8; 32]) -> bool {
        let lock = self.mn_list_stubs.read().unwrap();
        let result = lock.contains(&block_hash);
        println!("[CACHE] has_stub_for_masternode_list: {} = {result}", block_hash.to_hex());
        drop(lock);
        result
    }

    pub fn block_height_for_hash(&self, block_hash: [u8; 32]) -> Option<u32> {
        let lock = self.cached_block_hash_heights.read().unwrap();
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        println!("[CACHE] block_height_for_hash: {} = {}", block_hash.to_hex(), result.map_or("Unknown".to_string(), |h| h.to_string()));
        result
    }

    pub fn cache_block_height_for_hash(&self, block_hash: [u8; 32], height: u32) {
        let mut lock = self.cached_block_hash_heights.write().unwrap();
        //println!("[CACHE] cache_block_height_for_hash: {} = {height}", block_hash.to_hex());
        lock.insert(block_hash, height);
        drop(lock);
    }

    pub fn remove_all_masternode_lists(&self) {
        let mut lock = self.mn_lists.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.mn_list_stubs.write().unwrap();
        lock.clear();
        drop(lock);
        let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
        lock.clear();
        drop(lock);
    }

    pub fn active_quorum_of_type(&self, ty: LLMQType, hash: [u8; 32]) -> Option<LLMQEntry> {
        let lock = self.active_quorums.read().unwrap();
        let result = lock.iter().find(|q| q.llmq_type == ty && q.llmq_hash == hash).cloned();
        drop(lock);
        result
    }

    pub fn get_last_queried_block_hash(&self) -> [u8; 32] {
        let lock = self.last_queried_block_hash.read().unwrap();
        println!("[CACHE] get_last_queried_block_hash: {}", lock.to_hex());
        let result = lock.clone();
        drop(lock);
        result

    }
    pub fn set_last_queried_block_hash(&self, block_hash: [u8; 32]) {
        let mut lock = self.last_queried_block_hash.write().unwrap();
        println!("[CACHE] set_last_queried_block_hash: {}", block_hash.to_hex());
        *lock = block_hash;
        drop(lock);
    }
    pub fn get_last_queried_qr_masternode_list_at_tip(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_tip.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn has_last_queried_qr_masternode_list_at_tip(&self) -> bool {
        let lock = self.last_qr_list_at_tip.read().unwrap();
        let result = lock.is_some();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_tip(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_tip.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_tip(&self) {
        let mut lock = self.last_qr_list_at_tip.write().unwrap();
        *lock = None;
        drop(lock);
    }
    pub fn get_last_queried_qr_masternode_list_at_h(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_h.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_h(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_h.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_h(&self) {
        let mut lock = self.last_qr_list_at_h.write().unwrap();
        *lock = None;
        drop(lock);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_c(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_h_c.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_h_c(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_h_c.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_c(&self) {
        let mut lock = self.last_qr_list_at_h_c.write().unwrap();
        *lock = None;
        drop(lock);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_2c(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_h_2c.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_h_2c(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_h_2c.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_2c(&self) {
        let mut lock = self.last_qr_list_at_h_2c.write().unwrap();
        *lock = None;
        drop(lock)
    }
    pub fn get_last_queried_qr_masternode_list_at_h_3c(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_h_3c.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_h_3c(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_h_3c.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_3c(&self) {
        let mut lock = self.last_qr_list_at_h_3c.write().unwrap();
        *lock = None;
        drop(lock);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_4c(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_qr_list_at_h_4c.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_qr_masternode_list_at_h_4c(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_qr_list_at_h_4c.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_4c(&self) {
        let mut lock = self.last_qr_list_at_h_4c.write().unwrap();
        *lock = None;
        drop(lock);
    }
    pub fn get_last_queried_mn_masternode_list(&self) -> Option<Arc<MasternodeList>> {
        let lock = self.last_mn_list.read().unwrap();
        let result = lock.clone();
        drop(lock);
        result
    }
    pub fn set_last_queried_mn_masternode_list(&self, masternode_list: Arc<MasternodeList>) {
        let mut lock = self.last_mn_list.write().unwrap();
        *lock = Some(masternode_list);
        drop(lock);
    }
    pub fn clean_last_queried_mn_masternode_list(&self) {
        let mut lock = self.last_mn_list.write().unwrap();
        *lock = None;
        drop(lock);
    }

    pub fn mn_list_retrieval_queue(&self) -> IndexSet<[u8; 32]> {
        let lock = self.mn_list_retrieval_queue.read().unwrap();
        let result = lock.queue.clone();
        drop(lock);
        result
    }
    pub fn qr_info_retrieval_queue(&self) -> IndexSet<[u8; 32]> {
        let lock = self.qr_info_retrieval_queue.read().unwrap();
        let result = lock.queue.clone();
        drop(lock);
        result
    }

    pub fn has_latest_block_in_mn_list_retrieval_queue_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        let lock = self.mn_list_retrieval_queue.read().unwrap();
        let result = lock.has_latest_block_with_hash(block_hash);
        drop(lock);
        result
    }
    pub fn has_latest_block_in_qr_info_retrieval_queue_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        let lock = self.qr_info_retrieval_queue.read().unwrap();
        let result = lock.has_latest_block_with_hash(block_hash);
        drop(lock);
        result
    }
    pub fn mn_list_retrieval_queue_get_max_amount(&self) -> usize {
        let lock = self.mn_list_retrieval_queue.read().unwrap();
        let result = lock.max_amount;
        drop(lock);
        result
    }
    pub fn qr_info_retrieval_queue_get_max_amount(&self) -> usize {
        let lock = self.qr_info_retrieval_queue.read().unwrap();
        let result = lock.max_amount;
        drop(lock);
        result
    }
    pub fn mn_list_retrieval_queue_count(&self) -> usize {
        let lock = self.mn_list_retrieval_queue.read().unwrap();
        let result = lock.queue.len();
        drop(lock);
        result
    }
    pub fn qr_info_retrieval_queue_count(&self) -> usize {
        let lock = self.qr_info_retrieval_queue.read().unwrap();
        let result = lock.queue.len();
        drop(lock);
        result
    }

}
