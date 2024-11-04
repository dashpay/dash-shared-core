use std::ffi::c_void;
use std::io::{Read, Write, Error};
use dash_spv_masternode_processor::consensus::encode;
use dash_spv_masternode_processor::common::block::Block;
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use dash_spv_masternode_processor::ffi::boxer::boxed;
use dash_spv_masternode_processor::ffi::to::ToFFI;
use dash_spv_masternode_processor::ffi::unboxer::unbox_any;
use dash_spv_masternode_processor::tx::transaction::Transaction;

use crate::ffi::callbacks::HasChainLock;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dstx
// #[repr(C)]
#[derive(Clone, Debug)]
// #[ferment_macro::export]
pub struct CoinJoinBroadcastTx {
    pub tx: Transaction,
    pub pro_tx_hash: UInt256,
    pub signature: Option<Vec<u8>>,
    pub signature_time: i64,
    // memory only
    // when corresponding tx is 0-confirmed or conflicted, nConfirmedHeight is -1
    confirmed_height: i32,
}

impl CoinJoinBroadcastTx {
    pub fn new(tx: Transaction, pro_tx_hash: UInt256, signature: Option<Vec<u8>>, signature_time: i64) -> Self {
        Self {
            tx,
            pro_tx_hash,
            signature,
            signature_time,
            confirmed_height: -1,
        }
    }

    pub fn set_confirmed_height(&mut self, confirmed_height: i32) {
        self.confirmed_height = confirmed_height;
    }

    pub fn is_expired(&self, block: Block, has_chain_lock: HasChainLock, context: *const c_void) -> bool {
        // expire confirmed DSTXes after ~1h since confirmation or chainlocked confirmation
        if self.confirmed_height == -1 || (block.height as i32) < self.confirmed_height {
            return false; // not mined yet
        }

        if block.height as i32 - self.confirmed_height > 24 {
            return true; // mined more than an hour ago
        }

        return unsafe {
            let boxed_block = boxed(block.encode());
            let is_chain_locked = has_chain_lock(boxed_block, context);
            unbox_any(boxed_block);
            
            is_chain_locked
        }; 
    }
}

impl CoinJoinMessageType for CoinJoinBroadcastTx {
    fn get_message_type(&self) -> String {
        return "dstx".to_string();
    }
}

impl encode::Encodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        let tx_data = self.tx.to_data(); // TODO: consensus_encode
        writer.write_all(&tx_data)?;
        offset += tx_data.len();
        offset += self.pro_tx_hash.consensus_encode(&mut writer)?;
        offset += match self.signature {
            Some(ref signature) => signature.consensus_encode(&mut writer)?,
            None => 0
        };
        offset += self.signature_time.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let tx = Transaction::consensus_decode(&mut d)?;
        let pro_tx_hash = UInt256::consensus_decode(&mut d)?;
        let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        let signature_time = i64::consensus_decode(&mut d)?;

        Ok(CoinJoinBroadcastTx::new(tx, pro_tx_hash, signature, signature_time) )
    }
}
