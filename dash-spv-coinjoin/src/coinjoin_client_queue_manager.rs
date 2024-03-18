use std::{collections::HashMap, time::Instant};

use dash_spv_masternode_processor::{common::SocketAddress, crypto::UInt256, ffi::from::FromFFI, models::MasternodeEntry};
use ferment_interfaces::boxed;

use crate::{ffi::callbacks::{DestroyMasternode, MasternodeByHash, ValidMasternodeCount}, masternode_meta_data_manager::MasternodeMetadataManager, messages::CoinJoinQueueMessage};

pub struct CoinJoinClientQueueManager {
    coinjoin_queue: Vec<CoinJoinQueueMessage>,
    spamming_masternodes: HashMap<UInt256, u64>,
    masternode_metadata_manager: MasternodeMetadataManager,
    masternode_by_hash: MasternodeByHash,
    destroy_masternode: DestroyMasternode,
    valid_mns_count: ValidMasternodeCount,
    context: *const std::ffi::c_void
}

impl CoinJoinClientQueueManager {
    pub fn new(
        masternode_metadata_manager: MasternodeMetadataManager,
        masternode_by_hash: MasternodeByHash,
        destroy_masternode: DestroyMasternode,
        valid_mns_count: ValidMasternodeCount,
        context: *const std::ffi::c_void
    ) -> Self {
        Self {
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
        let current_time = Instant::now().elapsed().as_secs();
        self.coinjoin_queue.retain(|q| !q.is_time_out_of_bounds(current_time));
    }

    pub fn get_queue_item_and_try(&mut self) -> Option<CoinJoinQueueMessage> {
        for dsq in self.coinjoin_queue.iter_mut() {
            if !dsq.tried && !dsq.is_time_out_of_bounds(Instant::now().elapsed().as_secs()) {
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

        if dsq.is_time_out_of_bounds(Instant::now().elapsed().as_secs()) {
            return;
        }

        if let Some(dmn) = self.get_mn(dsq.pro_tx_hash) {
            if !dsq.check_signature(dmn.operator_public_key) {
                // add 10 points to ban score
                return;
            }


        }
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

    fn valid_mns_count(&self) -> u32 {
        unsafe { return (self.valid_mns_count)(self.context); }
    }

    fn is_try_submit_denominate(&self, dmn: &MasternodeEntry) -> bool {
        // TODO
        // foreach manager in CoinJoinClientManagers {
            // coinJoinClientManager.trySubmitDenominate(dmn.getService());
        // }

        return false;
    }
}