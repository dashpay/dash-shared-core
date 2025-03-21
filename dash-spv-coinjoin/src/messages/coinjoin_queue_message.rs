use std::io;
use std::io::{Cursor, Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::consensus::{Decodable, Encodable};
use dashcore::consensus::encode::{Error, VarInt};
use dashcore::hashes::{sha256d, Hash};
use dashcore::hash_types::ProTxHash;
use logging::*;
use dash_spv_crypto::keys::BLSKey;
use crate::coinjoin::CoinJoin;
use crate::messages::coinjoin_message::CoinJoinMessageType;

use crate::constants::COINJOIN_QUEUE_TIMEOUT;

// dsq
// A currently in progress mixing merge and denomination information
// #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
#[ferment_macro::export]
pub struct CoinJoinQueueMessage {
    pub denomination: u32,
    pub pro_tx_hash: ProTxHash,
    pub time: i64,
    pub ready: bool, // ready to submit
    pub signature: Option<BLSSignature>,
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
            self.pro_tx_hash.to_hex()
        )?;
        Ok(())
    }
}

impl CoinJoinQueueMessage {
    pub fn get_signature_hash(&self) -> sha256d::Hash {
        let mut writer = Vec::<u8>::new();
        self.denomination.consensus_encode(&mut writer).unwrap();
        self.pro_tx_hash.consensus_encode(&mut writer).unwrap();
        self.time.consensus_encode(&mut writer).unwrap();
        self.ready.consensus_encode(&mut writer).unwrap();
        sha256d::Hash::hash(&writer)
    }
}

#[ferment_macro::export]
impl CoinJoinQueueMessage {
    pub fn from_message(message: &[u8]) -> CoinJoinQueueMessage {
        let mut cursor = Cursor::new(message);
        CoinJoinQueueMessage::consensus_decode(&mut cursor).unwrap()
    }
    pub fn is_time_out_of_bounds(&self, current_time: u64) -> bool {
        current_time.saturating_sub(self.time as u64) > COINJOIN_QUEUE_TIMEOUT ||
            (self.time as u64).saturating_sub(current_time) > COINJOIN_QUEUE_TIMEOUT
    }

    pub fn check_signature(&self, key: [u8; 48], use_legacy: bool) -> bool {
        if let Some(ref signature) = self.signature {
            let hash = self.get_signature_hash();
            let verified = BLSKey::key_with_public_key(key, use_legacy).verify_insecure(hash.as_byte_array(), signature.as_bytes());
            if !verified {
                log_warn!(target: "CoinJoinQueue", "verifySignature failed");
            }

            return verified;
        }

        false
    }

}

impl CoinJoinMessageType for CoinJoinQueueMessage {
    fn get_message_type(&self) -> String {
        return "dsq".to_string();
    }
}

impl Encodable for CoinJoinQueueMessage {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.denomination.consensus_encode(writer)?;
        offset += self.pro_tx_hash.consensus_encode(writer)?;
        offset += self.time.consensus_encode(writer)?;
        offset += self.ready.consensus_encode(writer)?;
        offset += match self.signature {
            Some(ref signature) => {
                let len_offset = VarInt(signature.len() as u64).consensus_encode(writer)?;
                let sig_offset = signature.consensus_encode(writer)?;
                len_offset + sig_offset
            }
            None => 0
        };

        Ok(offset)
    }
}

impl Decodable for CoinJoinQueueMessage {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let denomination = u32::consensus_decode(d)?;
        let pro_tx_hash = ProTxHash::consensus_decode(d)?;
        let time = i64::consensus_decode(d)?;
        let ready: bool = bool::consensus_decode(d)?;
        let _signature_len = VarInt::consensus_decode(d)?;
        let signature: Option<BLSSignature> = BLSSignature::consensus_decode(d).ok();
        let message = CoinJoinQueueMessage { denomination, pro_tx_hash, time, ready, signature, tried: false };
        Ok(message)
    }
}