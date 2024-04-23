use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::crypto::byte_util::{AsBytes, UInt256};
use dash_spv_masternode_processor::consensus::{encode, Encodable};
use dash_spv_masternode_processor::crypto::UInt768;
use dash_spv_masternode_processor::hashes::hex::ToHex;
use dash_spv_masternode_processor::keys::{BLSKey, IKey};
use dash_spv_masternode_processor::models::OperatorPublicKey;

use crate::constants::COINJOIN_QUEUE_TIMEOUT;

// dsq
// A currently in progress mixing merge and denomination information
// #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
// #[ferment_macro::export]
pub struct CoinJoinQueueMessage {
    pub denomination: u32,
    pub pro_tx_hash: UInt256,
    pub time: i64,
    pub ready: bool, // ready to submit
    pub signature: Option<UInt768>,
    // Memory only
    pub tried: bool
}

impl CoinJoinQueueMessage {
    pub fn is_time_out_of_bounds(&self, current_time: i64) -> bool {
        return current_time.saturating_sub(self.time) as u64 > COINJOIN_QUEUE_TIMEOUT || 
            self.time.saturating_sub(current_time) as u64 > COINJOIN_QUEUE_TIMEOUT
    }

    pub fn check_signature(&self, key: OperatorPublicKey) -> bool { // TODO: recheck test
        if let Some(ref signature) = self.signature {
            let hash = self.get_signature_hash();
            println!("sig hash: {:?}", hash.as_bytes().to_hex());
            let verified = BLSKey::key_with_public_key(
                key.data, 
                key.is_legacy()
            ).verify(hash.as_bytes(), signature.as_bytes());

            if !verified {
                println!("[RUST] CoinJoinQueue-CheckSignature -- VerifyInsecure() failed");
            }

            return verified;
        } else {
            return false;
        }
    }

    pub fn get_signature_hash(&self) -> UInt256 {
        let mut writer = Vec::<u8>::new();
        self.denomination.consensus_encode(&mut writer).unwrap();
        self.pro_tx_hash.consensus_encode(&mut writer).unwrap();
        self.time.consensus_encode(&mut writer).unwrap();
        self.ready.consensus_encode(&mut writer).unwrap();
        UInt256::sha256d(&writer)
    }
}

impl encode::Encodable for CoinJoinQueueMessage {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.denomination.consensus_encode(&mut writer)?;
        offset += self.pro_tx_hash.consensus_encode(&mut writer)?;
        offset += self.time.consensus_encode(&mut writer)?;
        offset += self.ready.consensus_encode(&mut writer)?;
        offset += match self.signature {
            Some(ref signature) => signature.consensus_encode(&mut writer)?,
            None => 0
        };

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinQueueMessage {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let denomination = u32::consensus_decode(&mut d)?;
        let pro_tx_hash = UInt256::consensus_decode(&mut d)?;
        let time = i64::consensus_decode(&mut d)?;
        let ready: bool = bool::consensus_decode(&mut d)?;
        let signature: Option<UInt768> = UInt768::consensus_decode(&mut d).ok();
        
        Ok(CoinJoinQueueMessage { denomination, pro_tx_hash, time, ready, signature, tried: false })
    }
}
