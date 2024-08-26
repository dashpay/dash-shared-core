use std::collections::HashMap;
use dash_spv_masternode_processor::{common::SocketAddress, crypto::UInt256, ffi::{from::FromFFI, unboxer::unbox_any}, models::MasternodeEntry};
use ferment_interfaces::boxed;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{coinjoin_client_manager::CoinJoinClientManager, constants::COINJOIN_QUEUE_TIMEOUT, ffi::callbacks::{DestroyMasternode, MasternodeByHash, ValidMasternodeCount}, masternode_meta_data_manager::MasternodeMetadataManager, messages::CoinJoinQueueMessage};

pub struct CoinJoinClientQueueManager {
    client_manager_ptr: *mut CoinJoinClientManager,
    coinjoin_queue: Vec<CoinJoinQueueMessage>,
    spamming_masternodes: HashMap<UInt256, u64>,
    pub masternode_metadata_manager: MasternodeMetadataManager,
    masternode_by_hash: MasternodeByHash,
    destroy_masternode: DestroyMasternode,
    valid_mns_count: ValidMasternodeCount,
    context: *const std::ffi::c_void
}

impl CoinJoinClientQueueManager {
    pub fn new(
        client_manager_ptr: *mut CoinJoinClientManager,
        masternode_metadata_manager: MasternodeMetadataManager,
        masternode_by_hash: MasternodeByHash,
        destroy_masternode: DestroyMasternode,
        valid_mns_count: ValidMasternodeCount,
        context: *const std::ffi::c_void
    ) -> Self {
        Self {
            client_manager_ptr,
            coinjoin_queue: Vec::new(),
            spamming_masternodes: HashMap::new(),
            masternode_by_hash,
            destroy_masternode,
            masternode_metadata_manager,
            valid_mns_count,
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

    pub fn process_ds_queue(&mut self, from_peer: SocketAddress, mut dsq: CoinJoinQueueMessage) {
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
                    println!("[RUST] CoinJoin: DSQUEUE -- Peer {:?} is sending WAY too many dsq messages for a masternode {:?}", from_peer.ip_address, dsq.pro_tx_hash);
                }
                return;
            }
        }

        println!("[RUST] CoinJoin: DSQUEUE -- new {}", dsq);
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        if dsq.is_time_out_of_bounds(current_time) {
            println!("[RUST] CoinJoin: DSQUEUE time_out_of_bounds, time: {}, current_time: {}", dsq.time, current_time);
            return;
        }

        if let Some(dmn) = self.get_mn(dsq.pro_tx_hash) {
            if !dsq.check_signature(dmn.operator_public_key) {
                // add 10 points to ban score
                println!("[RUST] CoinJoin: DSQUEUE signature check failed");
                return;
            }

            // if the queue is ready, submit if we can
            if dsq.ready && self.try_submit_denominate(dmn.socket_address.clone()) {
                println!("[RUST] CoinJoin: DSQUEUE -- CoinJoin queue ({}) is ready on masternode {}", dsq, dmn.socket_address);
            } else {
                if let Some(meta_info) = self.masternode_metadata_manager.get_meta_info(dmn.provider_registration_transaction_hash, true) {
                    let last_dsq = meta_info.last_dsq;
                    let dsq_threshold = self.masternode_metadata_manager.get_dsq_threshold(dmn.provider_registration_transaction_hash, self.valid_mns_count());
                    println!("[RUST] CoinJoin: DSQUEUE -- lastDsq: {}  dsqThreshold: {}  dsqCount: {}", last_dsq, dsq_threshold, self.masternode_metadata_manager.dsq_count);
                    // don't allow a few nodes to dominate the queuing process
                    if last_dsq != 0 && dsq_threshold > self.masternode_metadata_manager.dsq_count {
                        if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                            self.spamming_masternodes.insert(dsq.pro_tx_hash, current_time);
                            println!("[RUST] CoinJoin: DSQUEUE -- Masternode {} is sending too many dsq messages", dmn.provider_registration_transaction_hash);
                        }
                        return;
                    }
                } else {
                    println!("[RUST] CoinJoin: DSQUEUE meta_info is None");
                    return;
                }

                self.masternode_metadata_manager.allow_mixing(dmn.provider_registration_transaction_hash);
                println!("[RUST] CoinJoin: DSQUEUE -- new CoinJoin queue ({}) from masternode {}", dsq, dmn.socket_address);
                
                self.mark_already_joined_queue_as_tried(&mut dsq);
                self.coinjoin_queue.push(dsq);
            }
        } else {
            println!("[RUST] CoinJoin: masternode entry is None");
        }
    }

    pub fn do_maintenance(&mut self) {
        self.check_queue();
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.spamming_masternodes.retain(|_, v| (*v + COINJOIN_QUEUE_TIMEOUT as u64) > current_time);
    }

    fn get_mn(&self, pro_tx_hash: UInt256) -> Option<MasternodeEntry> {
        unsafe { 
            let boxed_hash = boxed(pro_tx_hash.0);
            let mn = (self.masternode_by_hash)(boxed_hash, self.context);

            if mn.is_null() {
                return None;
            }

            let masternode = (*mn).decode();
            (self.destroy_masternode)(mn);
            unbox_any(boxed_hash);

            return Some(masternode);
        }
    }

    fn valid_mns_count(&self) -> u64 {
        unsafe { return (self.valid_mns_count)(self.context); }
    }

    fn try_submit_denominate(&mut self, mn_addr: SocketAddress) -> bool {
        unsafe { (*self.client_manager_ptr).try_submit_denominate(mn_addr) }
    }

    fn mark_already_joined_queue_as_tried(&mut self, dsq: &mut CoinJoinQueueMessage) -> bool {
        unsafe { (*self.client_manager_ptr).mark_already_joined_queue_as_tried(dsq) }
    }
}