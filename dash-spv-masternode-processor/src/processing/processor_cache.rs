use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, RwLock};
use hashes::hex::ToHex;
use dash_spv_crypto::llmq::LLMQEntry;
use dash_spv_crypto::network::LLMQType;
use crate::models::{llmq_indexed_hash::LLMQIndexedHash, masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};

#[derive(Clone, Default)]
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
        &mut self,
        r#type: LLMQType,
        block_hash: [u8; 32],
    ) -> Option<Vec<MasternodeEntry>> {
        let lock = self.llmq_members.read().unwrap();
        let map_by_type_opt = lock.get(&r#type);
        let mut maybe_members = None;
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref()?.get(&block_hash) {
                maybe_members = Some(members.clone());
            }
        }
        drop(lock);
        maybe_members
    }

    pub fn remove_quorum_members(&mut self, block_hash: &[u8; 32]) {
        let mut llmq_members_lock = self.llmq_members.write().unwrap();
        let mut llmq_indexed_members_lock = self.llmq_indexed_members.write().unwrap();
        llmq_members_lock.iter_mut().for_each(|(llmq_type, map)| {
            map.remove(block_hash);
        });
        drop(llmq_members_lock);
        llmq_indexed_members_lock.iter_mut().for_each(|(llmq_type, map)| {
            let empties = map
                .iter()
                .filter(|&(&k, _)| k.hash == *block_hash)
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();
            empties.iter().for_each(|h| {
                map.remove(h);
            });
        });
        drop(llmq_indexed_members_lock);
    }

}

/// Initialize opaque cache to store needed information between FFI calls
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_create_cache() -> *mut MasternodeProcessorCache {
    let cache = MasternodeProcessorCache::default();
    println!("processor_create_cache: {:?}", cache);
    ferment::boxed(cache)
}

/// Destroy opaque cache
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn processor_destroy_cache(cache: *mut MasternodeProcessorCache) {
    println!("processor_destroy_cache: {:?}", cache);
    let cache = ferment::unbox_any(cache);
}

#[ferment_macro::export]
impl MasternodeProcessorCache {
    pub fn clear(&self) {
        self.clear_current_lists();
        self.llmq_members.write().unwrap().clear();
        self.llmq_indexed_members.write().unwrap().clear();
        self.mn_lists.write().unwrap().clear();
        self.mn_list_stubs.write().unwrap().clear();
        self.llmq_snapshots.write().unwrap().clear();
        self.cl_signatures.write().unwrap().clear();
        self.needed_masternode_lists.write().unwrap().clear();
        self.list_awaiting_quorum_validation.write().unwrap().clear();
        self.list_needing_quorum_validation.write().unwrap().clear();
        self.cached_block_hash_heights.write().unwrap().clear();
        self.active_quorums.write().unwrap().clear();
        let mut lq = self.last_queried_block_hash.write().unwrap();
        *lq = [0u8; 32];
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

    pub fn maybe_snapshot(&self, block_hash: [u8; 32]) -> Option<LLMQSnapshot> {
        let lock = self.llmq_snapshots.read().unwrap();
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }
    pub fn maybe_cl_signature(&self, block_hash: [u8; 32]) -> Option<[u8; 96]> {
        let lock = self.cl_signatures.read().unwrap();
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }
    pub fn add_snapshot(&mut self, block_hash: [u8; 32], snapshot: LLMQSnapshot) {
        let mut lock = self.llmq_snapshots.write().unwrap();
        lock.insert(block_hash, snapshot);
        drop(lock);
    }
    pub fn remove_snapshot(&mut self, block_hash: &[u8; 32]) {
        let mut lock = self.llmq_snapshots.write().unwrap();
        lock.remove(block_hash);
        drop(lock);
    }
    pub fn add_cl_signature(&mut self, block_hash: [u8; 32], cl_signature: [u8; 96]) {
        let mut lock = self.cl_signatures.write().unwrap();
        lock.insert(block_hash, cl_signature);
        drop(lock);
    }
    pub fn remove_cl_signature(&mut self, block_hash: &[u8; 32]) {
        let mut lock = self.cl_signatures.write().unwrap();
        lock.remove(block_hash);
        drop(lock);
    }
    pub fn cl_signature(&self, block_hash: [u8; 32]) -> Option<[u8; 96]> {
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
        // lock.retain(|h| h.eq(&block_hash));
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

    // pub fn remove_list_awaiting_quorum_validation_if_eq(&self, block_hash: [u8; 32]) {
    //     let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
    //     if let Some(h) = lock.as_ref() {
    //         if h.eq(&block_hash) {
    //             *lock = None;
    //         }
    //     }
    // }

    pub fn add_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        println!("[CACHE] add_block_hash_for_list_needing_quorums_validated: {}", block_hash.to_hex());
        lock.insert(block_hash);
        drop(lock);
    }
    pub fn remove_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        // lock.retain(|h| block_hash.eq(&h));
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
        println!("[CACHE] masternode_list_by_block_hash: {}: {}", block_hash.to_hex(), result.as_ref().map(|b| b.block_hash.to_hex()).unwrap_or("None".to_string()));
        let result = lock.get(&block_hash).cloned();
        drop(lock);
        result
    }
    pub fn remove_masternode_list(&mut self, block_hash: [u8; 32]) {
        let mut lock = self.mn_lists.write().unwrap();
        println!("[CACHE] remove_masternode_list: {}", block_hash.to_hex());
        lock.remove(&block_hash);
        drop(lock);
    }
    pub fn remove_masternode_lists_before_height(&mut self, height: u32) {
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
        let lock = self.needed_masternode_lists.read().unwrap();
        println!("[CACHE] all_needed_masternode_list: {}", lock.iter().fold(String::new(), |mut acc, h| {
            acc.push_str(format!("{}, ", h.to_hex()).as_str());
            acc
        }));
        let result = lock.clone();
        drop(lock);
        result
    }

    pub fn clear_needed_masternode_lists(&mut self) {
        let mut lock = self.needed_masternode_lists.write().unwrap();
        lock.clear();
        drop(lock);
    }

    pub fn recent_masternode_lists(&self) -> Vec<Arc<MasternodeList>> {
        let lock = self.mn_lists.read().unwrap();
        let mut sorted = Vec::from_iter(lock.values().cloned());
        sorted.sort_by_key(|list| list.known_height);
        println!("[CACHE] all_needed_masternode_list: {}", sorted.iter().fold(String::new(), |mut acc, h| {
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
        println!("[CACHE] all_needed_masternode_list: {}", set.iter().fold(String::new(), |mut acc, h| {
            acc.push_str(format!("{}, ", h.to_hex()).as_str());
            acc
        }));
        drop(lists);
        drop(stubs);
        set
    }
    pub fn known_masternode_lists_count(&self) -> usize {
        let lists = self.mn_lists.read().unwrap();
        let stubs = self.mn_list_stubs.read().unwrap();
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
        let stubs_lock = self.mn_list_stubs.read().unwrap();
        let has_list = lists_lock.contains_key(&block_hash);
        let has_stub = stubs_lock.contains(&block_hash);
        drop(lists_lock);
        drop(stubs_lock);
        let result = has_list || has_stub;
        println!("[CACHE] has_masternode_list_at: {} {}", block_hash.to_hex(), result);
        result
    }

    pub fn masternode_list_loaded(&self, block_hash: [u8; 32], list: Arc<MasternodeList>) -> usize {
        let mut stubs_lock = self.mn_list_stubs.write().unwrap();
        stubs_lock.remove(&block_hash);
        drop(stubs_lock);
        let mut lists_lock = self.mn_lists.write().unwrap();
        // if lists_lock.contains_key(&block_hash) {
        //     println!("[CACHE] masternode_list at {} exist so -> merge", block_hash.to_hex());
        //     list
        // }
        lists_lock.insert(block_hash, list);
        let count = lists_lock.len();
        drop(lists_lock);
        println!("[CACHE] masternode_list_loaded: {} {}", block_hash.to_hex(), count);
        count
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
        println!("[CACHE] cache_block_height_for_hash: {} = {height}", block_hash.to_hex());
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


    pub fn maybe_merge_masternode_list(&self) {

    }
}

// We need to do this in order to work with proc macro for methods
// as when processing methods where MasternodeProcessorCache is declared as parameter
// it's transformed into MasternodeProcessorCache
pub type MasternodeProcessorCacheFFI = MasternodeProcessorCache;

impl ferment::FFIConversionFrom<MasternodeProcessorCache> for MasternodeProcessorCacheFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> MasternodeProcessorCache {
        panic!("It's not intended")
    }

    unsafe fn ffi_from(ffi: *mut Self) -> MasternodeProcessorCache {
        // After unboxing MasternodeProcessorCache we've taken back ownership of the memory in Rust
        // So we should not attempt to free or use the raw pointer in C again after this, as it would lead to undefined behavior
        // So we have to to re-box it and send it back to C again
        *ferment::unbox_any(ffi)
    }
}
impl ferment::FFIConversionTo<MasternodeProcessorCache> for MasternodeProcessorCacheFFI {
    unsafe fn ffi_to_const(obj: MasternodeProcessorCache) -> *const Self {
        ferment::boxed(obj)
    }

    unsafe fn ffi_to(obj: MasternodeProcessorCache) -> *mut Self {
        ferment::boxed(obj)
    }
}