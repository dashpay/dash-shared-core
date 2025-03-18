use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::raw::c_void;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use logging::*;
use crate::{coinjoin_client_manager::CoinJoinClientManager, constants::COINJOIN_QUEUE_TIMEOUT, masternode_meta_data_manager::MasternodeMetadataManager, messages::CoinJoinQueueMessage};

pub struct CoinJoinClientQueueManager {
    client_manager_ptr: *mut CoinJoinClientManager,
    coinjoin_queue: Vec<CoinJoinQueueMessage>,
    spamming_masternodes: HashMap<[u8; 32], u64>,
    pub masternode_metadata_manager: MasternodeMetadataManager,
    masternode_by_hash: Arc<dyn Fn(*const c_void, [u8; 32]) -> Option<QualifiedMasternodeListEntry>>,
    // destroy_masternode: DestroyMasternode,
    valid_mns_count: Arc<dyn Fn(*const c_void) -> u64>,
    context: *const std::ffi::c_void
}

impl CoinJoinClientQueueManager {
    pub fn new<
        MBH: Fn(*const c_void, [u8; 32]) -> Option<QualifiedMasternodeListEntry> + 'static,
        VMC: Fn(*const c_void) -> u64 + 'static,
    >(
        client_manager_ptr: *mut CoinJoinClientManager,
        masternode_metadata_manager: MasternodeMetadataManager,
        masternode_by_hash: MBH,
        // destroy_masternode: DestroyMasternode,
        valid_mns_count: VMC,
        context: *const std::ffi::c_void
    ) -> Self {
        Self {
            client_manager_ptr,
            coinjoin_queue: Vec::new(),
            spamming_masternodes: HashMap::new(),
            masternode_by_hash: Arc::new(masternode_by_hash),
            // destroy_masternode,
            masternode_metadata_manager,
            valid_mns_count: Arc::new(valid_mns_count),
            context
        }
    }

    pub fn set_null(&mut self) {
        self.coinjoin_queue.clear();
    }

    pub fn check_queue(&mut self) {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.coinjoin_queue.retain(|q| !q.is_time_out_of_bounds(current_time));
    }

    pub fn get_queue_item_and_try(&mut self) -> Option<CoinJoinQueueMessage> {
        for dsq in self.coinjoin_queue.iter_mut() {
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            if !dsq.tried && !dsq.is_time_out_of_bounds(current_time) {
                dsq.tried = true;
                return Some(dsq.clone());
            }
        }
        None
    }

    pub fn process_ds_queue(&mut self, from_peer: SocketAddr, mut dsq: CoinJoinQueueMessage) {
        // let mut client_manager = (*self.client_manager_ptr);

        // process every dsq only once
        for q in self.coinjoin_queue.iter() {
            if q == &dsq {
                return;
            }
            
            if q.ready == dsq.ready && q.pro_tx_hash == dsq.pro_tx_hash {
                // no way the same mn can send another dsq with the same readiness this soon
                if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    self.spamming_masternodes.insert(dsq.pro_tx_hash, current_time);
                    log_debug!(target: "CoinJoin", "Peer {:?} is sending WAY too many dsq messages for a masternode {:?}", from_peer.ip(), dsq.pro_tx_hash);
                }
                return;
            }
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if dsq.is_time_out_of_bounds(current_time) {
            return;
        }

        if let Some(dmn) = self.get_mn(dsq.pro_tx_hash) {
            if !dsq.check_signature(dmn.masternode_list_entry.operator_public_key) {
                // add 10 points to ban score
                return;
            }

            // if the queue is ready, submit if we can
            if dsq.ready && self.try_submit_denominate(dmn.masternode_list_entry.service_address.clone()) {
                log_info!(target: "CoinJoin", "CoinJoin queue ({}) is ready on masternode {}", dsq, dmn.masternode_list_entry.service_address);
            } else {
                if let Some(meta_info) = self.masternode_metadata_manager.get_meta_info(dmn.masternode_list_entry.pro_reg_tx_hash, true) {
                    let last_dsq = meta_info.last_dsq;
                    let dsq_threshold = self.masternode_metadata_manager.get_dsq_threshold(dmn.masternode_list_entry.pro_reg_tx_hash, self.valid_mns_count());

                    // don't allow a few nodes to dominate the queuing process
                    if last_dsq != 0 && dsq_threshold > self.masternode_metadata_manager.dsq_count {
                        if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                            self.spamming_masternodes.insert(dsq.pro_tx_hash, current_time);
                            log_info!(target: "CoinJoin", "Masternode {} is sending too many dsq messages", dmn.masternode_list_entry.pro_reg_tx_hash.to_string());
                        }
                        return;
                    }
                } else {
                    return;
                }

                self.masternode_metadata_manager.allow_mixing(dmn.masternode_list_entry.pro_reg_tx_hash);
                let log_msg = format!("new CoinJoin queue ({}) from masternode {}", dsq, dmn.masternode_list_entry.service_address.to_string());

                if dsq.ready {
                    log_info!(target: "CoinJoin", "{}", log_msg);
                } else {
                    log_debug!(target: "CoinJoin", "{}", log_msg);
                }

                self.mark_already_joined_queue_as_tried(&mut dsq);
                self.coinjoin_queue.push(dsq);
            }
        }
    }

    pub fn do_maintenance(&mut self) {
        self.check_queue();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.spamming_masternodes.retain(|_, v| (*v + COINJOIN_QUEUE_TIMEOUT) > current_time);
    }

    fn get_mn(&self, pro_tx_hash: [u8; 32]) -> Option<QualifiedMasternodeListEntry> {
        (self.masternode_by_hash)(self.context, pro_tx_hash)
        // unsafe {
        //     let boxed_hash = boxed(pro_tx_hash.0);
        //     let mn = (self.masternode_by_hash)(boxed_hash, self.context);
        //
        //     if mn.is_null() {
        //         return None;
        //     }
        //
        //     let masternode = (*mn).decode();
        //     (self.destroy_masternode)(mn);
        //     unbox_any(boxed_hash);
        //
        //     return Some(masternode);
        // }
    }

    fn valid_mns_count(&self) -> u64 {
        (self.valid_mns_count)(self.context)
    }

    fn try_submit_denominate(&mut self, mn_addr: SocketAddr) -> bool {
        unsafe { (*self.client_manager_ptr).try_submit_denominate(mn_addr) }
    }

    fn mark_already_joined_queue_as_tried(&mut self, dsq: &mut CoinJoinQueueMessage) -> bool {
        unsafe { (*self.client_manager_ptr).mark_already_joined_queue_as_tried(dsq) }
    }
}