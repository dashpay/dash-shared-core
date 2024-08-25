use std::io::{Error, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use dash_spv_masternode_processor::consensus::encode::VarInt;
use dash_spv_masternode_processor::crypto::byte_util::{Reversable, UInt256};
use dash_spv_masternode_processor::consensus::{encode, Encodable};
use dash_spv_masternode_processor::crypto::UInt768;
use dash_spv_masternode_processor::hashes::hex::ToHex;
use dash_spv_masternode_processor::hashes::{sha256d, Hash};
use dash_spv_masternode_processor::keys::BLSKey;
use dash_spv_masternode_processor::models::OperatorPublicKey;
use crate::coinjoin::CoinJoin;
use crate::messages::coinjoin_message::CoinJoinMessageType;

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

impl std::fmt::Display for CoinJoinQueueMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        write!(f, "CoinJoinQueue(denom={}[{}], t={}[exp={}], ready={}, proTxHash={})", 
            CoinJoin::denomination_to_string(self.denomination),
            self.denomination,
            self.time,
            self.is_time_out_of_bounds(current_time),
            self.ready,
            self.pro_tx_hash.reversed().0.to_hex().chars().take(16).collect::<String>()
        )?;
        Ok(())
    }
}

impl CoinJoinQueueMessage {
    pub fn is_time_out_of_bounds(&self, current_time: u64) -> bool {
        return current_time.saturating_sub(self.time as u64) > COINJOIN_QUEUE_TIMEOUT || 
            (self.time as u64).saturating_sub(current_time) > COINJOIN_QUEUE_TIMEOUT;
    }

    pub fn check_signature(&self, key: OperatorPublicKey) -> bool { // TODO: recheck test
        if let Some(ref signature) = self.signature {
            let hash = self.get_signature_hash();
            let verified = BLSKey::key_with_public_key(
                key.data, 
                key.is_legacy()
            ).verify_insecure(&hash, *signature);

            if !verified {
                println!("[RUST] CoinJoinQueue-verifySignature failed");
            }

            return verified;
        }

        return false;
    }

    pub fn get_signature_hash(&self) -> Vec<u8> {
        let mut writer = Vec::<u8>::new();
        self.denomination.consensus_encode(&mut writer).unwrap();
        self.pro_tx_hash.consensus_encode(&mut writer).unwrap();
        self.time.consensus_encode(&mut writer).unwrap();
        self.ready.consensus_encode(&mut writer).unwrap();
        sha256d::Hash::hash(&writer).into_inner().to_vec()
    }
}

impl CoinJoinMessageType for CoinJoinQueueMessage {
    fn get_message_type(&self) -> String {
        return "dsq".to_string();
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
            Some(ref signature) => {
                let len_offset = VarInt(signature.0.len() as u64).consensus_encode(&mut writer)?;
                let sig_offset = signature.consensus_encode(&mut writer)?;
                len_offset + sig_offset
            }
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
        let _signature_len = VarInt::consensus_decode(&mut d)?;
        let signature: Option<UInt768> = UInt768::consensus_decode(&mut d).ok();
        let message = CoinJoinQueueMessage { denomination, pro_tx_hash, time, ready, signature, tried: false };
        Ok(message)
    }
}