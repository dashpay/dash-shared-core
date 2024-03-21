use std::{collections::HashMap, time::Instant};

use dash_spv_masternode_processor::{common::SocketAddress, crypto::UInt256, ffi::from::FromFFI, models::MasternodeEntry};
use ferment_interfaces::boxed;

use crate::{constants::COINJOIN_QUEUE_TIMEOUT, ffi::callbacks::{DestroyMasternode, IsBlockchainSynced, MasternodeByHash, ValidMasternodeCount}, masternode_meta_data_manager::MasternodeMetadataManager, messages::CoinJoinQueueMessage, models::CoinJoinClientOptions};

pub struct CoinJoinClientQueueManager {
    coinjoin_queue: Vec<CoinJoinQueueMessage>,
    spamming_masternodes: HashMap<UInt256, u64>,
    masternode_metadata_manager: MasternodeMetadataManager,
    coinjoin_options: CoinJoinClientOptions,
    masternode_by_hash: MasternodeByHash,
    destroy_masternode: DestroyMasternode,
    valid_mns_count: ValidMasternodeCount,
    is_synced: IsBlockchainSynced,
    context: *const std::ffi::c_void
}

impl CoinJoinClientQueueManager {
    pub fn new(
        masternode_metadata_manager: MasternodeMetadataManager,
        coinjoin_options: CoinJoinClientOptions,
        masternode_by_hash: MasternodeByHash,
        destroy_masternode: DestroyMasternode,
        valid_mns_count: ValidMasternodeCount,
        is_synced: IsBlockchainSynced,
        context: *const std::ffi::c_void
    ) -> Self {
        Self {
            coinjoin_queue: Vec::new(),
            spamming_masternodes: HashMap::new(),
            masternode_by_hash,
            destroy_masternode,
            masternode_metadata_manager,
            coinjoin_options,
            valid_mns_count,
            is_synced,
            context
        }
    }

    pub fn set_null(&mut self) {
        self.coinjoin_queue.clear();
    }

    pub fn check_queue(&mut self) {
        let current_time = Instant::now().elapsed().as_secs();
        self.coinjoin_queue.retain(|q| !q.is_time_out_of_bounds(current_time as i64));
    }

    pub fn get_queue_item_and_try(&mut self) -> Option<CoinJoinQueueMessage> {
        for dsq in self.coinjoin_queue.iter_mut() {
            if !dsq.tried && !dsq.is_time_out_of_bounds(Instant::now().elapsed().as_secs() as i64) {
                dsq.tried = true;
                return Some(dsq.clone());
            }
        }
        None
    }

    pub fn process_ds_queue(&mut self, from_peer: SocketAddress, dsq: CoinJoinQueueMessage) {
        // process every dsq only once
        for q in self.coinjoin_queue.iter() {
            if q == &dsq {
                return;
            }
            
            if q.ready == dsq.ready && q.pro_tx_hash == dsq.pro_tx_hash {
                // no way the same mn can send another dsq with the same readiness this soon
                if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                    self.spamming_masternodes.insert(dsq.pro_tx_hash, Instant::now().elapsed().as_secs());
                    println!("[RUST] CoinJoin: DSQUEUE -- Peer {:?} is sending WAY too many dsq messages for a masternode {:?}", from_peer.ip_address, dsq.pro_tx_hash);
                }
                return;
            }
        }

        println!("[RUST] CoinJoin: DSQUEUE -- {:?} new", dsq);

        if dsq.is_time_out_of_bounds(Instant::now().elapsed().as_secs() as i64) {
            return;
        }

        if let Some(dmn) = self.get_mn(dsq.pro_tx_hash) {
            if !dsq.check_signature(dmn.operator_public_key) {
                // add 10 points to ban score
                return;
            }


            // if the queue is ready, submit if we can
            if dsq.ready && self.is_try_submit_denominate(&dmn) {
                println!("[RUST] CoinJoin: DSQUEUE -- CoinJoin queue ({:?}) is ready on masternode {}", dsq, dmn.socket_address);
            } else {
                if let Some(meta_info) = self.masternode_metadata_manager.get_meta_info(dmn.provider_registration_transaction_hash, true) {
                    let last_dsq = meta_info.last_dsq;
                    let dsq_threshold = self.masternode_metadata_manager.get_dsq_threshold(dmn.provider_registration_transaction_hash, self.valid_mns_count());
                    println!("[RUST] CoinJoin: DSQUEUE -- lastDsq: {}  dsqThreshold: {}  dsqCount: {}", last_dsq, dsq_threshold, self.masternode_metadata_manager.dsq_count);
                    // don't allow a few nodes to dominate the queuing process
                    if last_dsq != 0 && dsq_threshold > self.masternode_metadata_manager.dsq_count {
                        if !self.spamming_masternodes.contains_key(&dsq.pro_tx_hash) {
                            self.spamming_masternodes.insert(dsq.pro_tx_hash, Instant::now().elapsed().as_secs());
                            println!("[RUST] CoinJoin: DSQUEUE -- Masternode {} is sending too many dsq messages", dmn.provider_registration_transaction_hash);
                        }
                        return;
                    }
                } else {
                    return;
                }

                self.masternode_metadata_manager.allow_mixing(dmn.provider_registration_transaction_hash);
                println!("[RUST] CoinJoin: DSQUEUE -- new CoinJoin queue ({:?}) from masternode {}", dsq, dmn.socket_address);
                
                // TODO
                // foreach manager in CoinJoinClientManagers {
                    // coinJoinClientManager.markAlreadyJoinedQueueAsTried(dsq);
                // }

                self.coinjoin_queue.push(dsq);
            }
        }
    }

    pub fn do_maintainence(&mut self) {
        if !self.coinjoin_options.enable_coinjoin {
            return;
        }

        if !self.is_synced() {
            return;
        }

        self.check_queue();
        self.spamming_masternodes.retain(|_, v| (*v + COINJOIN_QUEUE_TIMEOUT as u64) > Instant::now().elapsed().as_secs());
    }

    fn get_mn(&self, pro_tx_hash: UInt256) -> Option<MasternodeEntry> {
        unsafe { 
            let mn = (self.masternode_by_hash)(boxed(pro_tx_hash.0), self.context);

            if mn.is_null() {
                return None;
            }

            let masternode = (*mn).decode();
            (self.destroy_masternode)(mn);
            
            return Some(masternode);
        }
    }

    fn valid_mns_count(&self) -> u64 {
        unsafe { return (self.valid_mns_count)(self.context); }
    }

    fn is_try_submit_denominate(&self, dmn: &MasternodeEntry) -> bool {
        // TODO
        // foreach manager in CoinJoinClientManagers {
            // coinJoinClientManager.trySubmitDenominate(dmn.getService());
        // }

        return false;
    }

    fn is_synced(&self) -> bool {
        unsafe { return (self.is_synced)(self.context); }
    }
}