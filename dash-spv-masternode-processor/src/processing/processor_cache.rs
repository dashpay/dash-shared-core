use std::collections::BTreeMap;
use ferment_interfaces::FFIConversion;
use crate::chain::common::llmq_type::LLMQType;
use crate::crypto::byte_util::{UInt256, UInt768};
use crate::models::{llmq_indexed_hash::LLMQIndexedHash, masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};

#[derive(Clone, Default)]
#[ferment_macro::opaque]
pub struct MasternodeProcessorCache {
    pub llmq_members: BTreeMap<LLMQType, BTreeMap<UInt256, Vec<MasternodeEntry>>>,
    pub llmq_indexed_members: BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>,
    pub mn_lists: BTreeMap<UInt256, MasternodeList>,
    pub llmq_snapshots: BTreeMap<UInt256, LLMQSnapshot>,
    pub cl_signatures: BTreeMap<UInt256, UInt768>,
    pub needed_masternode_lists: Vec<UInt256>,
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
            .finish()
    }
}

impl MasternodeProcessorCache {
    pub fn clear(&mut self) {
        self.llmq_members.clear();
        self.llmq_indexed_members.clear();
        self.mn_lists.clear();
        self.llmq_snapshots.clear();
        self.needed_masternode_lists.clear();
        self.cl_signatures.clear();
    }
    pub fn add_masternode_list(&mut self, block_hash: UInt256, list: MasternodeList) {
        self.mn_lists.insert(block_hash, list);
    }
    pub fn remove_masternode_list(&mut self, block_hash: &UInt256) {
        self.mn_lists.remove(block_hash);
    }
    pub fn add_snapshot(&mut self, block_hash: UInt256, snapshot: LLMQSnapshot) {
        self.llmq_snapshots.insert(block_hash, snapshot);
    }
    pub fn remove_snapshot(&mut self, block_hash: &UInt256) {
        self.llmq_snapshots.remove(block_hash);
    }
    pub fn add_cl_signature(&mut self, block_hash: UInt256, cl_signature: UInt768) {
        self.cl_signatures.insert(block_hash, cl_signature);
    }
    pub fn remove_cl_signature(&mut self, block_hash: &UInt256) {
        self.cl_signatures.remove(block_hash);
    }
    pub fn get_quorum_members_of_type(
        &mut self,
        r#type: LLMQType,
    ) -> Option<&mut BTreeMap<UInt256, Vec<MasternodeEntry>>> {
        self.llmq_members.get_mut(&r#type)
    }

    pub fn get_indexed_quorum_members_of_type(
        &mut self,
        r#type: LLMQType,
    ) -> Option<&mut BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>> {
        self.llmq_indexed_members.get_mut(&r#type)
    }

    pub fn get_quorum_members(
        &mut self,
        r#type: LLMQType,
        block_hash: UInt256,
    ) -> Option<Vec<MasternodeEntry>> {
        let map_by_type_opt = self.get_quorum_members_of_type(r#type);
        if map_by_type_opt.is_some() {
            if let Some(members) = map_by_type_opt.as_ref().unwrap().get(&block_hash) {
                return Some(members.clone());
            }
        }
        None
    }

    pub fn remove_quorum_members(&mut self, block_hash: &UInt256) {
        self.llmq_members.iter_mut().for_each(|(llmq_type, map)| {
            map.remove(block_hash);
        });
        self.llmq_indexed_members.iter_mut().for_each(|(llmq_type, map)| {
            let empties = map
                .iter()
                .filter(|&(&k, _)| k.hash == *block_hash)
                .map(|(k, _)| *k)
                .collect::<Vec<_>>();
            empties.iter().for_each(|h| {
                map.remove(h);
            });
        });
    }
}

// We need to do this in order to work with proc macro for methods
// as when processing methods where MasternodeProcessorCache is declared as parameter
// it's transformed into MasternodeProcessorCache
pub type MasternodeProcessorCacheFFI = MasternodeProcessorCache;

impl FFIConversion<MasternodeProcessorCache> for MasternodeProcessorCacheFFI {
    unsafe fn ffi_from_const(ffi: *const Self) -> MasternodeProcessorCache {
        panic!("It's not intended")
    }

    unsafe fn ffi_to_const(obj: MasternodeProcessorCache) -> *const Self {
        ferment_interfaces::boxed(obj)
    }

    unsafe fn ffi_from(ffi: *mut Self) -> MasternodeProcessorCache {
        // After unboxing MasternodeProcessorCache we've taken back ownership of the memory in Rust
        // So we should not attempt to free or use the raw pointer in C again after this, as it would lead to undefined behavior
        // So we have to to re-box it and send it back to C again
        *ferment_interfaces::unbox_any(ffi)
    }

    unsafe fn ffi_to(obj: MasternodeProcessorCache) -> *mut Self {
        ferment_interfaces::boxed(obj)
    }
}
