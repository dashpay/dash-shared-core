use std::cmp;
use std::collections::{BTreeMap, HashSet};
use std::collections::btree_map::Entry;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};
use hashes::hex::ToHex;
use indexmap::IndexSet;
use dash_spv_crypto::llmq::{LLMQEntry, LLMQEntryValidationStatus};
use dash_spv_crypto::network::{IHaveChainSettings, LLMQType};
use crate::models::{llmq_indexed_hash::LLMQIndexedHash, masternode_entry::MasternodeEntry, masternode_list::MasternodeList, snapshot::LLMQSnapshot};
use crate::models::masternode_entry::{previous_entry_hashes_to_string, previous_operator_public_keys_to_string, previous_validity_to_string};
use crate::processing::{CoreProvider, MasternodeProcessor};

#[derive(Clone, Default)]
#[ferment_macro::export]
pub struct RetrievalQueue {
    pub queue: IndexSet<[u8; 32]>,
    pub max_amount: usize,
}

impl Display for RetrievalQueue {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let Self { queue, max_amount } = self;
        let s = if queue.is_empty() {
            format!("\t\t\tqueue (0/{max_amount})\n")
        } else {
            let s = queue.iter().fold(String::new(), |mut acc, hash| {
                acc.push_str(format!("\t\t{}\n", hash.to_hex()).as_str());
                acc
            });
            format!("\t\t\tqueue ({}/{max_amount}):\n {s}\n", queue.len())
        };
        f.write_str(s.as_str())
    }
}

impl RetrievalQueue {
    pub fn has_latest_block_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        self.queue.last().map(|last| block_hash.eq(last)).unwrap_or(false)
    }
    pub fn first(&self) -> Option<[u8; 32]> {
        self.queue.first().cloned()
    }
    pub fn remove_one(&mut self, block_hash: &[u8; 32]) -> bool {
        self.queue.shift_remove(block_hash)
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
        // processor.provider.notify_sync_state(CacheState::queue(self.queue.len(), self.max_amount));
    }

    pub fn clear(&mut self) {
        self.queue.clear();
        self.max_amount = 0;
    }
}

pub trait RwLockHelper {
    fn read_lock<F, I, O>(lock: Arc<RwLock<I>>, reader: F) -> O
    where
        F: FnOnce(&I) -> O {
        let lock = lock.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    fn write_lock<F, I, O>(lock: Arc<RwLock<I>>, writer: F) -> O
    where
        F: FnOnce(&mut I) -> O {
        let mut lock = lock.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }
}

#[ferment_macro::opaque]
pub struct MasternodeProcessorCache {
    pub dispatcher: Arc<dyn CoreProvider>,

    pub llmq_members: Arc<RwLock<BTreeMap<LLMQType, BTreeMap<[u8; 32], Vec<MasternodeEntry>>>>>,
    pub llmq_indexed_members: Arc<RwLock<BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>>>,
    pub mn_lists: Arc<RwLock<BTreeMap<[u8; 32], MasternodeList>>>,
    pub mn_list_stubs: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub llmq_snapshots: Arc<RwLock<BTreeMap<[u8; 32], LLMQSnapshot>>>,
    pub active_llmq: Arc<RwLock<HashSet<LLMQEntry>>>,
    pub cl_signatures: Arc<RwLock<BTreeMap<[u8; 32], [u8; 96]>>>,
    pub needed_masternode_lists: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub list_awaiting_quorum_validation: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub list_needing_quorum_validation: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub cached_block_hash_heights: Arc<RwLock<BTreeMap<[u8; 32], u32>>>,
    //last by height, not by time queried
    pub last_queried_block_hash: Arc<RwLock<[u8; 32]>>,

    pub mn_list_retrieval_queue: Arc<RwLock<RetrievalQueue>>,
    pub qr_info_retrieval_queue: Arc<RwLock<RetrievalQueue>>,

    pub last_qr_list_at_tip: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_qr_list_at_h: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_qr_list_at_h_c: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_qr_list_at_h_2c: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_qr_list_at_h_3c: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_qr_list_at_h_4c: Arc<RwLock<Option<[u8; 32]>>>,
    pub last_mn_list: Arc<RwLock<Option<[u8; 32]>>>,

}

impl std::fmt::Debug for MasternodeProcessorCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}] [CACHE]", self.dispatcher.chain_type().name()).as_str())
    }
}


impl MasternodeProcessorCache {

    pub fn new(dispatcher: Arc<dyn CoreProvider>) -> Self {
        Self {
            dispatcher,
            llmq_members: Arc::new(Default::default()),
            llmq_indexed_members: Arc::new(Default::default()),
            mn_lists: Arc::new(Default::default()),
            mn_list_stubs: Arc::new(Default::default()),
            llmq_snapshots: Arc::new(Default::default()),
            active_llmq: Arc::new(Default::default()),
            cl_signatures: Arc::new(Default::default()),
            needed_masternode_lists: Arc::new(Default::default()),
            list_awaiting_quorum_validation: Arc::new(Default::default()),
            list_needing_quorum_validation: Arc::new(Default::default()),
            cached_block_hash_heights: Arc::new(Default::default()),
            last_queried_block_hash: Arc::new(Default::default()),
            mn_list_retrieval_queue: Arc::new(Default::default()),
            qr_info_retrieval_queue: Arc::new(Default::default()),
            last_qr_list_at_tip: Arc::new(Default::default()),
            last_qr_list_at_h: Arc::new(Default::default()),
            last_qr_list_at_h_c: Arc::new(Default::default()),
            last_qr_list_at_h_2c: Arc::new(Default::default()),
            last_qr_list_at_h_3c: Arc::new(Default::default()),
            last_qr_list_at_h_4c: Arc::new(Default::default()),
            last_mn_list: Arc::new(Default::default())


        }
    }

    pub fn read_llmq_members<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<LLMQType, BTreeMap<[u8; 32], Vec<MasternodeEntry>>>) -> R {
        let lock = self.llmq_members.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_llmq_members<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<LLMQType, BTreeMap<[u8; 32], Vec<MasternodeEntry>>>) -> O {
        let mut lock = self.llmq_members.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_llmq_indexed_members<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>) -> R {
        let lock = self.llmq_indexed_members.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_llmq_indexed_members<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<LLMQType, BTreeMap<LLMQIndexedHash, Vec<MasternodeEntry>>>) -> O {
        let mut lock = self.llmq_indexed_members.write().unwrap();
        let result= writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_active_llmq<F, R>(&self, reader: F) -> R
    where F: FnOnce(&HashSet<LLMQEntry>) -> R {
        let lock = self.active_llmq.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_active_llmq<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut HashSet<LLMQEntry>) -> O {
        let mut lock = self.active_llmq.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_llmq_snapshots<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<[u8; 32], LLMQSnapshot>) -> R {
        let lock = self.llmq_snapshots.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_llmq_snapshots<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<[u8; 32], LLMQSnapshot>) -> O {
        let mut lock = self.llmq_snapshots.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_mn_lists<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<[u8; 32], MasternodeList>) -> R {
        let lock = self.mn_lists.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_mn_lists<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<[u8; 32], MasternodeList>) -> O {
        let mut lock = self.mn_lists.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_mn_list_stubs<F, R>(&self, reader: F) -> R
    where F: FnOnce(&HashSet<[u8; 32]>) -> R {
        let lock = self.mn_list_stubs.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_mn_list_stubs<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut HashSet<[u8; 32]>) -> O {
        let mut lock = self.mn_list_stubs.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_cl_signatures<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<[u8; 32], [u8; 96]>) -> R {
        let lock = self.cl_signatures.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_cl_signatures<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<[u8; 32], [u8; 96]>) -> O {
        let mut lock = self.cl_signatures.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_needed_masternode_lists<F, R>(&self, reader: F) -> R where F: FnOnce(&HashSet<[u8; 32]>) -> R {
        let lock = self.needed_masternode_lists.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_needed_masternode_lists<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut HashSet<[u8; 32]>) -> O {
        let mut lock = self.needed_masternode_lists.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_list_awaiting_quorum_validation<F, R>(&self, reader: F) -> R
    where F: FnOnce(&HashSet<[u8; 32]>) -> R {
        let lock = self.list_awaiting_quorum_validation.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_list_awaiting_quorum_validation<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut HashSet<[u8; 32]>) -> O {
        let mut lock = self.list_awaiting_quorum_validation.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_list_needing_quorum_validation<F, R>(&self, reader: F) -> R
    where F: FnOnce(&HashSet<[u8; 32]>) -> R {
        let lock = self.list_needing_quorum_validation.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_list_needing_quorum_validation<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut HashSet<[u8; 32]>) -> O {
        let mut lock = self.list_needing_quorum_validation.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_cached_block_hash_heights<F, R>(&self, reader: F) -> R
    where F: FnOnce(&BTreeMap<[u8; 32], u32>) -> R {
        let lock = self.cached_block_hash_heights.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_cached_block_hash_heights<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut BTreeMap<[u8; 32], u32>) -> O {
        let mut lock = self.cached_block_hash_heights.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_last_queried_block_hash<F, R>(&self, reader: F) -> R where F: FnOnce(&[u8; 32]) -> R {
        let lock = self.last_queried_block_hash.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_queried_block_hash<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut [u8; 32]) -> O {
        let mut lock = self.last_queried_block_hash.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }


    pub fn read_mn_list_retrieval_queue<F, R>(&self, reader: F) -> R
    where F: FnOnce(&RetrievalQueue) -> R {
        let lock = self.mn_list_retrieval_queue.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_mn_list_retrieval_queue<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut RetrievalQueue) -> O {
        let mut lock = self.mn_list_retrieval_queue.write().unwrap();
        let result = writer(&mut lock);
        println!("{self:?} {}", lock.to_string());
        drop(lock);
        result
    }

    pub fn read_qr_info_retrieval_queue<F, R>(&self, reader: F) -> R
    where F: FnOnce(&RetrievalQueue) -> R {
        let lock = self.qr_info_retrieval_queue.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_qr_info_retrieval_queue<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut RetrievalQueue) -> O {
        let mut lock = self.qr_info_retrieval_queue.write().unwrap();
        let result = writer(&mut lock);
        println!("{self:?} {}", lock.to_string());
        drop(lock);
        result
    }

    pub fn read_last_qr_list_at_tip<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_tip.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_tip<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_tip.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_last_qr_list_at_h<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_h.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_h<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_h.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }
    pub fn read_last_qr_list_at_h_c<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_h_c.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_h_c<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_h_c.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }
    pub fn read_last_qr_list_at_h_2c<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_h_2c.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_h_2c<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_h_2c.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }
    pub fn read_last_qr_list_at_h_3c<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_h_3c.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_h_3c<F, O>(&self, writer: F) -> O where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_h_3c.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }
    pub fn read_last_qr_list_at_h_4c<F, R>(&self, reader: F) -> R where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_qr_list_at_h_4c.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_qr_list_at_h_4c<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_qr_list_at_h_4c.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }

    pub fn read_last_mn_list<F, R>(&self, reader: F) -> R
    where F: FnOnce(&Option<[u8; 32]>) -> R {
        let lock = self.last_mn_list.read().unwrap();
        let result = reader(&lock);
        drop(lock);
        result
    }

    pub fn write_last_mn_list<F, O>(&self, writer: F) -> O
    where F: FnOnce(&mut Option<[u8; 32]>) -> O {
        let mut lock = self.last_mn_list.write().unwrap();
        let result = writer(&mut lock);
        drop(lock);
        result
    }





    pub fn get_quorum_members(
        &self,
        r#type: LLMQType,
        block_hash: [u8; 32],
    ) -> Option<Vec<MasternodeEntry>> {
        self.read_llmq_members(|lock| lock.get(&r#type)?.get(&block_hash).cloned())
    }

    pub fn remove_quorum_members(&self, block_hash: &[u8; 32]) {
        self.write_llmq_members(|lock| {
            lock.iter_mut().for_each(|(llmq_type, map)| {
                map.remove(block_hash);
            });
        });
        self.write_llmq_indexed_members(|lock| {
            lock.iter_mut().for_each(|(llmq_type, map)| {
                let empties = map
                    .iter()
                    .filter_map(|(k, _)| k.hash.eq(block_hash).then_some(k.clone()))
                    .collect::<Vec<_>>();
                empties.iter().for_each(|h| {
                    map.remove(h);
                });
            });
        });
    }

}
#[ferment_macro::export]
impl MasternodeProcessorCache {

    pub fn active_llmq_description(&self) -> String {
        let s = self.read_active_llmq(|lock| lock.iter().fold(String::new(), |mut acc, LLMQEntry { llmq_type, llmq_hash, verified, ..}| {
            acc.push_str(format!("\t\t{llmq_type}: {}: {}\n", llmq_hash.to_hex(), verified).as_str());
            acc
        }));
        format!("\tactive llmq:\n{s}")
    }
    pub fn llmq_snapshots_description(&self) -> String {
        let s = self.read_llmq_snapshots(|lock| lock.iter().fold(String::new(), |mut acc, (h, s)| {
            acc.push_str(format!("\t\t{}: {s}\n", h.to_hex()).as_str());
            acc
        }));
        format!("\tllmq snapshots:\n{s}")
    }
    pub fn cl_signatures_description(&self) -> String {
        let s = self.read_cl_signatures(|lock| lock.iter().fold(String::new(), |mut acc, (hash, sig)| {
            acc.push_str(format!("\t\t{}: {}\n", hash.to_hex(), sig.to_hex()).as_str());
            acc
        }));
        format!("\tcl signatures:\n{s}")
    }

    pub fn needed_masternode_lists_description(&self) -> String {
        let s = self.read_needed_masternode_lists(|set| set.iter().fold(String::new(), |mut acc, hash| {
            acc.push_str(format!("\t\t{}\n", hash.to_hex()).as_str());
            acc
        }));
        format!("\tmasternode lists (needed):\n{s}")
    }
    pub fn list_awaiting_quorum_validation_description(&self) -> String {
        let s = self.read_list_awaiting_quorum_validation(|set| set.iter().fold(String::new(), |mut acc, hash| {
            acc.push_str(format!("\t\t{}\n", hash.to_hex()).as_str());
            acc
        }));
        format!("\tmasternode lists (awaiting llmq validation):\n{s}")
    }
    pub fn list_needing_quorum_validation_description(&self) -> String {
        let s = self.read_list_needing_quorum_validation(|set| set.iter().fold(String::new(), |mut acc, hash| {
            acc.push_str(format!("\t\t{}\n", hash.to_hex()).as_str());
            acc
        }));
        format!("\tmasternode lists (needing llmq validation):\n{s}")
    }
    pub fn stubs_description(&self) -> String {
        let s = self.read_mn_list_stubs(|set| set.iter().fold(String::new(), |mut acc, hash| {
            acc.push_str(format!("\t\t{}\n", hash.to_hex()).as_str());
            acc
        }));
        format!("\tmasternode lists (stubs):\n{s}")
    }
    pub fn last_queried_block_hash_description(&self) -> String {
        let s = self.read_last_queried_block_hash(|lock| lock.to_hex());
        format!("\tlast queried: {s}\n")
    }

    pub fn lists_description(&self) -> String {
        let s = self.read_mn_lists(|lock| lock.iter().fold(String::new(), |mut acc, (hash, list)| {
            acc.push_str(list.short_description().as_str());
            acc
        }));
        format!("\tmasternode lists (cached):\n{s}")
    }
    pub fn lists_short_description(&self) -> String {
        let s = self.read_mn_lists(|lock| lock.iter().fold(String::new(), |mut acc, (hash, list)| {
            acc.push_str(list.very_short_description().as_str());
            acc
        }));
        format!("\tmasternode lists (cached):\n{s}")
    }

    pub fn last_queried_lists_description(&self) -> String {
        let descript = |list: &Arc<RwLock<Option<[u8; 32]>>>| {
            let lock = list.read().unwrap();
            let desc = lock.as_ref().map_or("None".to_string(), |l|  l.to_hex());
            drop(lock);
            desc
        };
        let mut debug_string = String::new();
        debug_string.push_str(format!("\t\t\t\t   diff: {}\n", descript(&self.last_mn_list)).as_str());
        debug_string.push_str(format!("\t\t\t\t    tip: {}\n", descript(&self.last_qr_list_at_tip)).as_str());
        debug_string.push_str(format!("\t\t\t\tat    h: {}\n", descript(&self.last_qr_list_at_h)).as_str());
        debug_string.push_str(format!("\t\t\t\tat  h-c: {}\n", descript(&self.last_qr_list_at_h_c)).as_str());
        debug_string.push_str(format!("\t\t\t\tat h-2c: {}\n", descript(&self.last_qr_list_at_h_2c)).as_str());
        debug_string.push_str(format!("\t\t\t\tat h-3c: {}\n", descript(&self.last_qr_list_at_h_3c)).as_str());
        debug_string.push_str(format!("\t\t\t\tat h-4c: {}\n", descript(&self.last_qr_list_at_h_4c)).as_str());

        format!("\tlast queried:\n{debug_string}")
    }

    pub fn queue_description(&self) -> String {
        let descript = |queue: &Arc<RwLock<RetrievalQueue>>| {
            let lock = queue.read().unwrap();
            let desc = format!("{}", lock.to_string());
            drop(lock);
            desc
        };
        let mut debug_string = String::new();
        debug_string.push_str(format!("\t\t\t\t     diff: {}\n", descript(&self.mn_list_retrieval_queue)).as_str());
        debug_string.push_str(format!("\t\t\t\t   qr info: {}\n", descript(&self.qr_info_retrieval_queue)).as_str());
        debug_string
    }

    pub fn print_description(&self) {
        let mut debug_string = String::new();
        debug_string.push_str(self.last_queried_block_hash_description().as_str());
        debug_string.push_str(self.active_llmq_description().as_str());
        debug_string.push_str(self.cl_signatures_description().as_str());
        debug_string.push_str(self.needed_masternode_lists_description().as_str());
        debug_string.push_str(self.stubs_description().as_str());
        debug_string.push_str(self.lists_description().as_str());
        debug_string.push_str(self.last_queried_lists_description().as_str());
        debug_string.push_str(self.queue_description().as_str());
        debug_string.push_str(self.llmq_snapshots_description().as_str());

        println!("{self:?} status: \n{debug_string}");
    }

    pub fn print_needed_masternode_lists_description(&self) {
        println!("{self:?} {}", self.needed_masternode_lists_description());
    }
    pub fn print_last_queried_lists_description(&self) {
        println!("{self:?} {}", self.last_queried_lists_description());
    }

    pub fn print_queue_description(&self) {
        println!("{self:?} {}", self.queue_description());
    }

    pub fn print_lists_description(&self) {
        println!("{self:?} {}", self.lists_description());
    }

    pub fn print_lists_short_description(&self) {
        println!("{self:?} {}", self.lists_short_description());
    }

    pub fn clear_llmq_members(&self) {
        self.write_llmq_members(BTreeMap::clear)
    }
    pub fn clear_llmq_indexed_members(&self) {
        self.write_llmq_indexed_members(BTreeMap::clear);
    }
    pub fn clear_masternode_lists(&self) {
        self.write_mn_lists(BTreeMap::clear);
    }
    pub fn clear_masternode_list_stubs(&self) {
        self.write_mn_list_stubs(HashSet::clear);
    }
    pub fn clear_needed_masternode_lists(&self) {
        self.write_needed_masternode_lists(HashSet::clear);
    }
    pub fn clear_llmq_snapshots(&self) {
        self.write_llmq_snapshots(BTreeMap::clear);
    }
    pub fn clear_cl_signatures(&self) {
        self.write_cl_signatures(BTreeMap::clear);
    }
    pub fn clear_list_awaiting_quorum_validation(&self) {
        self.write_list_awaiting_quorum_validation(HashSet::clear);
    }
    pub fn clear_list_needing_quorum_validation(&self) {
        self.write_list_needing_quorum_validation(HashSet::clear);
    }
    pub fn clear_cached_block_hash_heights(&self) {
        self.write_cached_block_hash_heights(BTreeMap::clear);
    }
    pub fn clear_active_llmq(&self) {
        self.write_active_llmq(HashSet::clear);
    }
    pub fn clear_last_queried_block_hash(&self) {
        self.write_last_queried_block_hash(|lock| { *lock = [0u8; 32]; });
    }
    pub fn clear_mn_list_retrieval_queue(&self) {
        self.write_mn_list_retrieval_queue(RetrievalQueue::clear);
        println!("{self:?} queue: cleared");
    }
    pub fn clear_qr_info_retrieval_queue(&self) {
        self.write_qr_info_retrieval_queue(RetrievalQueue::clear);
    }
    pub fn clear(&self) {
        self.clear_current_lists();
        self.clear_llmq_members();
        self.clear_llmq_indexed_members();
        self.clear_masternode_lists();
        self.clear_masternode_list_stubs();
        self.clear_llmq_snapshots();
        self.clear_cl_signatures();
        self.clear_needed_masternode_lists();
        self.clear_list_awaiting_quorum_validation();
        self.clear_list_needing_quorum_validation();
        self.clear_active_llmq();

        self.clear_last_queried_block_hash();
        self.clear_mn_list_retrieval_queue();
        self.clear_qr_info_retrieval_queue();
        self.clear_cached_block_hash_heights();
    }
    pub fn clear_current_lists(&self) {
        self.write_last_qr_list_at_tip(|lock| *lock = None);
        self.write_last_qr_list_at_h(|lock| *lock = None);
        self.write_last_qr_list_at_h_c(|lock| *lock = None);
        self.write_last_qr_list_at_h_2c(|lock| *lock = None);
        self.write_last_qr_list_at_h_3c(|lock| *lock = None);
        self.write_last_qr_list_at_h_4c(|lock| *lock = None);
        self.write_last_mn_list(|lock| *lock = None);
    }

    pub fn masternode_list_loaded(&self, block_hash: [u8; 32], list: MasternodeList) -> usize {
        self.write_mn_list_stubs(|lock| lock.remove(&block_hash));
        self.write_mn_lists(|lock| {
            lock.insert(block_hash, list);
            lock.len()
        })
    }


    pub fn maybe_snapshot(&self, block_hash: [u8; 32]) -> Option<LLMQSnapshot> {
        self.read_llmq_snapshots(|lock| lock.get(&block_hash).cloned())
    }
    pub fn add_snapshot(&self, block_hash: [u8; 32], snapshot: LLMQSnapshot) {
        self.write_llmq_snapshots(|lock| lock.insert(block_hash, snapshot));
    }
    pub fn remove_snapshot(&self, block_hash: &[u8; 32]) {
        self.write_llmq_snapshots(|lock| lock.remove(block_hash));
    }
    pub fn add_cl_signature(&self, block_hash: [u8; 32], cl_signature: [u8; 96]) {
        self.write_cl_signatures(|lock| lock.insert(block_hash, cl_signature));
    }
    pub fn maybe_cl_signature(&self, block_hash: [u8; 32]) -> Option<[u8; 96]> {
        self.read_cl_signatures(|lock| lock.get(&block_hash).cloned())
    }

    pub fn remove_from_awaiting_quorum_validation_list(&self, block_hash: [u8; 32]) {
        self.write_list_awaiting_quorum_validation(|lock| lock.remove(&block_hash));
    }
    pub fn has_in_awaiting_quorum_validation_list(&self, block_hash: [u8; 32]) -> bool {
        self.read_list_awaiting_quorum_validation(|lock| lock.contains(&block_hash))
    }
    pub fn add_to_awaiting_quorum_validation_list(&self, hash: [u8; 32]) {
        self.write_list_awaiting_quorum_validation(|lock| lock.insert(hash));
    }

    pub fn add_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        self.write_list_needing_quorum_validation(|lock| lock.insert(block_hash));
    }
    pub fn remove_block_hash_for_list_needing_quorums_validated(&self, block_hash: [u8; 32]) {
        self.write_list_needing_quorum_validation(|lock| lock.remove(&block_hash));
    }

    pub fn has_list_at_block_hash_needing_quorums_validated(&self, block_hash: [u8; 32]) -> bool {
        self.read_list_needing_quorum_validation(|lock| lock.contains(&block_hash))
    }

    pub fn add_masternode_list(&self, block_hash: [u8; 32], list: MasternodeList) -> usize {
        self.write_mn_lists(|lock| {
            let old_count = lock.len();
            let h = list.known_height;
            match lock.entry(block_hash) {
                Entry::Vacant(vacant) => {
                    vacant.insert(list);
                    println!("{self:?} add_masternode_list (new): {h}: {} count: {old_count} + 1", block_hash.to_hex());
                }
                Entry::Occupied(mut occupied) => {
                    let old = occupied.get_mut();
                    let mut mn_diff = format!("{self:?} add_masternode_list (merge): {h}: {} count: {old_count}\n", block_hash.to_hex());
                    list.masternodes.iter().for_each(|(pro_tx_hash, node)| {
                        if let Some(old_entry) = old.masternodes.get(pro_tx_hash) {
                            if !node.mn_type.eq(&old_entry.mn_type) {
                                mn_diff.push_str(&format!("{} --> {}\n", old_entry.mn_type, node.mn_type));
                            }
                            if !node.socket_address.eq(&old_entry.socket_address) {
                                mn_diff.push_str(&format!("{}:{} --> {}:{}\n", old_entry.socket_address.ip_address.to_hex(), old_entry.socket_address.port, node.socket_address.ip_address.to_hex(), node.socket_address.port));
                            }
                            if node.is_valid != old_entry.is_valid {
                                mn_diff.push_str(&format!("valid: {} --> {}\n", old_entry.is_valid, node.is_valid));
                            }
                            if node.update_height != old_entry.update_height {
                                mn_diff.push_str(&format!("update_height: {} --> {}\n", old_entry.update_height, node.update_height));
                            }
                            if node.known_confirmed_at_height != old_entry.known_confirmed_at_height {
                                mn_diff.push_str(&format!("confirmed_at_height: {} --> {}\n", old_entry.known_confirmed_at_height.unwrap_or_default(), node.known_confirmed_at_height.unwrap_or_default()));
                            }
                            if !node.provider_registration_transaction_hash.eq(&old_entry.provider_registration_transaction_hash) {
                                mn_diff.push_str(&format!("pro_reg_tx_hash: {} --> {}\n", old_entry.provider_registration_transaction_hash.to_hex(), node.provider_registration_transaction_hash.to_hex()));
                            }
                            if !node.operator_public_key.eq(&old_entry.operator_public_key) {
                                mn_diff.push_str(&format!("pk: v{} {} --> v{} {}\n", old_entry.operator_public_key.version, old_entry.operator_public_key.data.to_hex(), node.operator_public_key.version, node.operator_public_key.data.to_hex()));
                            }
                            if !node.key_id_voting.eq(&old_entry.key_id_voting) {
                                mn_diff.push_str(&format!("key_id: {} --> {}\n", old_entry.key_id_voting.to_hex(), node.key_id_voting.to_hex()));
                            }
                            if !node.platform_node_id.eq(&old_entry.platform_node_id) {
                                mn_diff.push_str(&format!("evo_node_id: {} --> {}\n", old_entry.platform_node_id.to_hex(), node.platform_node_id.to_hex()));
                            }
                            if !node.confirmed_hash.eq(&old_entry.confirmed_hash) {
                                mn_diff.push_str(&format!("confirmed_hash: {} --> {}\n", old_entry.confirmed_hash.to_hex(), node.confirmed_hash.to_hex()));
                            }
                            if !node.entry_hash.eq(&old_entry.entry_hash) {
                                mn_diff.push_str(&format!("entry_hash: {} --> {}\n", old_entry.entry_hash.to_hex(), node.entry_hash.to_hex()));
                            }
                            if node.platform_http_port != old_entry.platform_http_port {
                                mn_diff.push_str(&format!("platform_http_port: {} --> {}\n", old_entry.platform_http_port, node.platform_http_port));
                            }
                            if node.confirmed_hash_hashed_with_provider_registration_transaction_hash != old_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash {
                                mn_diff.push_str(&format!("confirmed_hash_hashed_with_provider_registration_transaction_hash: {} --> {}\n", old_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.map(|h| h.to_hex()).unwrap_or("".to_string()), node.confirmed_hash_hashed_with_provider_registration_transaction_hash.map(|h| h.to_hex()).unwrap_or("".to_string())));
                            }
                            let node_prev_keys = previous_operator_public_keys_to_string(&node.previous_operator_public_keys);
                            let old_prev_keys = previous_operator_public_keys_to_string(&old_entry.previous_operator_public_keys);
                            if !node_prev_keys.eq(&old_prev_keys) {
                                mn_diff.push_str(&format!("prev pk: {} --> {}\n", old_prev_keys, node_prev_keys));
                            }
                            let node_prev_eh = previous_entry_hashes_to_string(&node.previous_entry_hashes);
                            let old_prev_eh = previous_entry_hashes_to_string(&old_entry.previous_entry_hashes);
                            if !node_prev_eh.eq(&old_prev_eh) {
                                mn_diff.push_str(&format!("prev entry_hashes: {} --> {}\n", old_prev_eh, node_prev_eh));
                            }
                            let node_prev_val = previous_validity_to_string(&node.previous_validity);
                            let old_prev_val = previous_validity_to_string(&old_entry.previous_validity);
                            if !node_prev_val.eq(&old_prev_val) {
                                mn_diff.push_str(&format!("prev validity: {} --> {}\n", old_prev_val, node_prev_val));
                            }
                        }
                    });
                    list.quorums.iter().for_each(|(llmq_type, map)| {
                        if let Some(old_quorums_of_type) = old.quorums.get(llmq_type) {
                            map.iter().for_each(|(llmq_hash, entry)| {
                                if let Some(old_entry) = old_quorums_of_type.get(llmq_hash) {
                                    let mut diff = String::new();
                                    if entry.version != old_entry.version {
                                        diff.push_str(&format!("version: {} --> {}\n", old_entry.version.index(), entry.version.index()));
                                    }
                                    if !entry.llmq_hash.eq(&old_entry.llmq_hash) {
                                        diff.push_str(&format!("llmq_hash: {} --> {}\n", old_entry.llmq_hash.to_hex(), entry.llmq_hash.to_hex()));
                                    }
                                    if !entry.index.eq(&old_entry.index) {
                                        diff.push_str(&format!("index: {} --> {}\n", old_entry.index, entry.index));
                                    }
                                    if !entry.public_key.eq(&old_entry.public_key) {
                                        diff.push_str(&format!("pk: {} --> {}\n", old_entry.public_key.to_hex(), entry.public_key.to_hex()));
                                    }
                                    if !entry.threshold_signature.eq(&old_entry.threshold_signature) {
                                        diff.push_str(&format!("ts: {} --> {}\n", old_entry.threshold_signature.to_hex(), entry.threshold_signature.to_hex()));
                                    }
                                    if !entry.verification_vector_hash.eq(&old_entry.verification_vector_hash) {
                                        diff.push_str(&format!("vv: {} --> {}\n", old_entry.verification_vector_hash.to_hex(), entry.verification_vector_hash.to_hex()));
                                    }
                                    if !entry.all_commitment_aggregated_signature.eq(&old_entry.all_commitment_aggregated_signature) {
                                        diff.push_str(&format!("asig: {} --> {}\n", old_entry.all_commitment_aggregated_signature.to_hex(), entry.all_commitment_aggregated_signature.to_hex()));
                                    }
                                    if !entry.all_commitment_aggregated_signature.eq(&old_entry.all_commitment_aggregated_signature) {
                                        diff.push_str(&format!("asig: {} --> {}\n", old_entry.all_commitment_aggregated_signature.to_hex(), entry.all_commitment_aggregated_signature.to_hex()));
                                    }
                                    if !entry.signers.eq(&old_entry.signers) {
                                        diff.push_str(&format!("signers: {}::{} --> {}::{}\n", old_entry.signers.count, old_entry.signers.bitset.to_hex(), entry.signers.count, entry.signers.bitset.to_hex()));
                                    }
                                    if !entry.valid_members.eq(&old_entry.valid_members) {
                                        diff.push_str(&format!("valid_members: {}::{} --> {}::{}\n", old_entry.valid_members.count, old_entry.valid_members.bitset.to_hex(), entry.valid_members.count, entry.valid_members.bitset.to_hex()));
                                    }
                                    if !entry.entry_hash.eq(&old_entry.entry_hash) {
                                        diff.push_str(&format!("entry_hash: {} --> {}\n", old_entry.entry_hash.to_hex(), entry.entry_hash.to_hex()));
                                    }
                                    if !entry.commitment_hash.eq(&old_entry.commitment_hash) {
                                        diff.push_str(&format!("commitment_hash: {} --> {}\n", old_entry.commitment_hash.map(|h|h.to_hex()).unwrap_or("None".to_string()), entry.commitment_hash.map(|h|h.to_hex()).unwrap_or("None".to_string())));
                                    }
                                    // if !diff.is_empty() {
                                    //     println!("LLMQ diff:\n{}\n\t", diff);
                                    // }
                                }
                            });
                        }
                    });
                    // if !mn_diff.is_empty() {
                    //     println!("{mn_diff}");
                    // }
                    let old_list = occupied.get_mut();
                    old_list.masternodes.iter_mut().for_each(|(hash, old_entry)| {
                        if let Some(new_entry) = list.masternodes.get(hash) {
                            old_entry.merged_with_new_entry(new_entry, list.known_height);
                        }
                    });

                    // We should merge only quorums actually
                    old_list.quorums.iter_mut().for_each(|(llmq_type, old_map)| {
                        old_map.iter_mut().for_each(|(llmq_hash, old_entry)| {
                            if let Some(new_map) = list.quorums.get(llmq_type) {
                                if let Some(new_entry) = new_map.get(llmq_hash) {
                                    let mut debug_string = String::new();
                                    if new_entry.is_verified() && old_entry.is_not_verified() {
                                        old_entry.verified = LLMQEntryValidationStatus::Verified;
                                        debug_string.push_str("verified");
                                    }
                                    if !old_entry.commitment_hash.eq(&new_entry.commitment_hash) {
                                        debug_string.push_str(format!("(commitment_hash: {})", new_entry.commitment_hash.as_ref().map_or("None".to_string(), |h| h.to_hex())).as_str());
                                        old_entry.commitment_hash = new_entry.commitment_hash;
                                    }
                                    if !debug_string.is_empty() {
                                        println!("{self:?} add_masternode_list (llmq merge): {llmq_type}: {}: {}", new_entry.llmq_hash_hex(), debug_string);
                                    }
                                }
                            }
                        });
                    });
                }
            }
            lock.len()
        })
    }

    pub fn masternode_list_by_block_hash(&self, block_hash: [u8; 32]) -> Option<MasternodeList> {
        self.read_mn_lists(|lock| {
            lock.get(&block_hash).cloned()
        })
    }
    pub fn remove_masternode_list(&self, block_hash: [u8; 32]) {
        self.write_mn_lists(|lock| {
            lock.remove(&block_hash);
        });
    }
    pub fn remove_masternode_lists_before_height(&self, height: u32) {
        self.write_mn_lists(|lock| {
            lock.retain(|_, value| value.known_height >= height);
        });
    }

    pub fn contains_block_hash_needing_masternode_list(&self, block_hash: [u8; 32]) -> bool {
        self.read_needed_masternode_lists(|lock| lock.iter().any(|h| block_hash.eq(h)))
    }
    pub fn has_block_hashes_needing_masternode_list(&self) -> bool {
        self.read_needed_masternode_lists(|lock| !lock.is_empty())
    }
    pub fn all_needed_masternode_list(&self) -> HashSet<[u8; 32]> {
        let b_lock = self.cached_block_hash_heights.read().unwrap();
        let lock = self.needed_masternode_lists.read().unwrap();
        println!("{self:?} all_needed_masternode_list: {}", lock.iter().fold(String::new(), |mut acc, h| {
            acc.push_str(format!("\t{}:{},\n", b_lock.get(h).unwrap_or(&u32::MAX), h.to_hex()).as_str());
            acc
        }));
        let result = lock.clone();
        drop(b_lock);
        drop(lock);
        result
    }

    pub fn add_needed_masternode_lists(&self, lists: HashSet<[u8; 32]>) {
        self.write_needed_masternode_lists(|lock| lock.extend(lists))
    }

    pub fn find_llmq_entry_public_key(&self, llmq_type: LLMQType, llmq_hash: [u8; 32]) -> Option<[u8; 48]> {
        self.read_mn_lists(|lock| {
            let mut sorted = Vec::from_iter(lock.values());
            sorted.sort_by_key(|list| list.known_height);
            for list in sorted.iter().rev() {
                if let Some(LLMQEntry { public_key, .. }) = list.quorum_entry_of_type_for_quorum_hash(llmq_type, llmq_hash) {
                    println!("{self:?} find_llmq_entry_public_key: Found in list at {} {}: {} = {}", list.known_height, llmq_type, llmq_hash.to_hex(), public_key.to_hex());
                    return Some(public_key.clone());
                }
            }
            println!("{self:?} find_llmq_entry_public_key: Not Found {}: {}", llmq_type, llmq_hash.to_hex());
            None
        })
    }

    pub fn recent_masternode_lists(&self) -> Vec<MasternodeList> {
        self.read_mn_lists(|lock| {
            let mut sorted = Vec::from_iter(lock.values().cloned());
            sorted.sort_by_key(|list| list.known_height);
            // println!("[CACHE] recent_masternode_lists: {}", sorted.iter().fold(String::new(), |mut acc, h| {
            //     acc.push_str(format!("{}, ", h.known_height).as_str());
            //     acc
            // }));
            sorted
        })
    }

    pub fn known_masternode_lists_block_hashes(&self) -> HashSet<[u8; 32]> {
        let list_hashes = self.read_mn_lists(|lock| lock.clone().into_keys());
        let stub_hashes = self.read_mn_list_stubs(|lock| lock.clone());
        let mut set = HashSet::<[u8; 32]>::from_iter(list_hashes);
        set.extend(stub_hashes);
        set
    }
    pub fn known_masternode_lists_count(&self) -> usize {
        let list_hashes = self.read_mn_lists(|lock| lock.clone().into_keys());
        let stub_hashes = self.read_mn_list_stubs(|lock| lock.clone());
        let mut set = HashSet::<[u8; 32]>::from_iter(list_hashes);
        set.extend(stub_hashes);
        set.len()
    }

    pub fn stored_masternode_lists_count(&self) -> usize {
        self.read_mn_lists(|lock| lock.len())
    }

    pub fn has_masternode_list_at(&self, block_hash: [u8; 32]) -> bool {
        let has_list = self.read_mn_lists(|lock| lock.contains_key(&block_hash));
        if has_list {
            return true
        }
        let has_stub = self.read_mn_list_stubs(|lock| lock.contains(&block_hash));
        has_stub
    }

    pub fn add_stub_for_masternode_list(&self, block_hash: [u8; 32]) {
        self.write_mn_list_stubs(|lock| lock.insert(block_hash));
    }
    pub fn remove_stub_for_masternode_list(&self, block_hash: [u8; 32]) {
        self.write_mn_list_stubs(|lock| lock.remove(&block_hash));
    }

    pub fn has_stub_for_masternode_list(&self, block_hash: [u8; 32]) -> bool {
        self.read_mn_list_stubs(|lock| lock.contains(&block_hash))
    }

    pub fn block_height_for_hash(&self, block_hash: [u8; 32]) -> Option<u32> {
        self.read_cached_block_hash_heights(|lock| lock.get(&block_hash).cloned())
    }

    pub fn cache_block_height_for_hash(&self, block_hash: [u8; 32], height: u32) {
        self.write_cached_block_hash_heights(|lock| lock.insert(block_hash, height));
    }

    pub fn remove_all_masternode_lists(&self) {
        self.write_mn_lists(BTreeMap::clear);
        self.write_mn_list_stubs(HashSet::clear);
        self.clear_list_awaiting_quorum_validation();
    }

    pub fn active_quorum_of_type(&self, ty: LLMQType, hash: [u8; 32]) -> Option<LLMQEntry> {
        self.read_active_llmq(|lock| lock.iter().find(|q| q.llmq_type == ty && q.llmq_hash == hash).cloned())
    }

    pub fn get_last_queried_block_hash(&self) -> [u8; 32] {
        self.read_last_queried_block_hash(|lock|  lock.clone())
    }
    pub fn set_last_queried_block_hash(&self, block_hash: [u8; 32]) {
        self.write_last_queried_block_hash(|lock| *lock = block_hash );
    }
    pub fn get_last_queried_qr_masternode_list_at_tip(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_tip(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn has_last_queried_qr_masternode_list_at_tip(&self) -> bool {
        self.read_last_qr_list_at_tip(Option::is_some)
    }
    pub fn set_last_queried_qr_masternode_list_at_tip(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_tip(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_tip(&self) {
        self.write_last_qr_list_at_tip(|lock| *lock = None);
    }
    pub fn get_last_queried_qr_masternode_list_at_h(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_h(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn has_last_queried_qr_masternode_list_at_h(&self) -> bool {
        self.read_last_qr_list_at_h(Option::is_some)
    }
    pub fn set_last_queried_qr_masternode_list_at_h(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_h(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_h(&self) {
        self.write_last_qr_list_at_h(|lock| *lock = None);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_c(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_h_c(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn set_last_queried_qr_masternode_list_at_h_c(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_h_c(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_c(&self) {
        self.write_last_qr_list_at_h_c(|lock| *lock = None);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_2c(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_h_2c(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn set_last_queried_qr_masternode_list_at_h_2c(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_h_2c(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_2c(&self) {
        self.write_last_qr_list_at_h_2c(|lock| *lock = None);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_3c(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_h_3c(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn set_last_queried_qr_masternode_list_at_h_3c(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_h_3c(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_3c(&self) {
        self.write_last_qr_list_at_h_3c(|lock| *lock = None);
    }
    pub fn get_last_queried_qr_masternode_list_at_h_4c(&self) -> Option<MasternodeList> {
        self.read_last_qr_list_at_h_4c(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn set_last_queried_qr_masternode_list_at_h_4c(&self, list_block_hash: [u8; 32]) {
        self.write_last_qr_list_at_h_4c(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_qr_masternode_list_at_h_4c(&self) {
        self.write_last_qr_list_at_h_4c(|lock| *lock = None);
    }
    pub fn get_last_queried_mn_masternode_list(&self) -> Option<MasternodeList> {
        self.read_last_mn_list(|lock| lock.clone())
            .and_then(|block_hash: [u8; 32]| self.masternode_list_by_block_hash(block_hash))
    }
    pub fn set_last_queried_mn_masternode_list(&self, list_block_hash: [u8; 32]) {
        self.write_last_mn_list(|lock| *lock = Some(list_block_hash));
    }
    pub fn clean_last_queried_mn_masternode_list(&self) {
        self.write_last_mn_list(|lock| *lock = None);
    }

    pub fn mn_list_retrieval_queue(&self) -> IndexSet<[u8; 32]> {
        self.read_mn_list_retrieval_queue(|lock| lock.queue.clone())
    }
    pub fn qr_info_retrieval_queue(&self) -> IndexSet<[u8; 32]> {
        self.read_qr_info_retrieval_queue(|lock| lock.queue.clone())
    }

    pub fn has_latest_block_in_mn_list_retrieval_queue_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        self.read_mn_list_retrieval_queue(|lock| lock.has_latest_block_with_hash(block_hash))
    }
    pub fn has_latest_block_in_qr_info_retrieval_queue_with_hash(&self, block_hash: &[u8; 32]) -> bool {
        self.read_qr_info_retrieval_queue(|lock| lock.has_latest_block_with_hash(block_hash))
    }
    pub fn mn_list_retrieval_queue_get_max_amount(&self) -> usize {
        self.read_mn_list_retrieval_queue(|lock| lock.max_amount)
    }
    pub fn qr_info_retrieval_queue_get_max_amount(&self) -> usize {
        self.read_qr_info_retrieval_queue(|lock| lock.max_amount)
    }
    pub fn mn_list_retrieval_queue_count(&self) -> usize {
        self.read_mn_list_retrieval_queue(|lock| lock.queue.len())
    }
    pub fn qr_info_retrieval_queue_count(&self) -> usize {
        self.read_qr_info_retrieval_queue(|lock| lock.queue.len())
    }

    pub fn update_masternode_list_known_height(&self, list_block_hash: [u8; 32], new_known_height: u32) {
        self.write_mn_lists(|lock| {
            if let Some(list) = lock.get_mut(&list_block_hash) {
                list.known_height = new_known_height;
            }
        });
    }
}
