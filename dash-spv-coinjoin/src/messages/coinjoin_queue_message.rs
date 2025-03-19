use std::io;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use dashcore::consensus::{Decodable, Encodable};
use dashcore::consensus::encode::Error;
use dashcore::hashes::{sha256d, Hash};
use dashcore::prelude::DisplayHex;
use dashcore::VarInt;
use logging::*;
use dash_spv_crypto::crypto::byte_util::Reversed;
use dash_spv_crypto::keys::BLSKey;
use crate::coinjoin::CoinJoin;
use crate::messages::coinjoin_message::CoinJoinMessageType;

use crate::constants::COINJOIN_QUEUE_TIMEOUT;

// dsq
// A currently in progress mixing merge and denomination information
// #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoinJoinQueueMessage {
    pub denomination: u32,
    pub pro_tx_hash: [u8; 32],
    pub time: i64,
    pub ready: bool, // ready to submit
    pub signature: Option<[u8; 96]>,
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
            self.pro_tx_hash.reversed().to_lower_hex_string()
        )?;
        Ok(())
    }
}

impl CoinJoinQueueMessage {
    pub fn is_time_out_of_bounds(&self, current_time: u64) -> bool {
        return current_time.saturating_sub(self.time as u64) > COINJOIN_QUEUE_TIMEOUT || 
            (self.time as u64).saturating_sub(current_time) > COINJOIN_QUEUE_TIMEOUT;
    }

    pub fn check_signature(&self, key: [u8; 48]) -> bool {
        if let Some(ref signature) = self.signature {
            let hash = self.get_signature_hash();
            let verified = BLSKey::key_with_public_key(key, false).verify_insecure(hash.as_byte_array(), signature);
            if !verified {
                log_warn!(target: "CoinJoinQueue", "verifySignature failed");
            }

            return verified;
        }

        false
    }

    pub fn get_signature_hash(&self) -> sha256d::Hash {
        let mut writer = Vec::<u8>::new();
        self.denomination.consensus_encode(&mut writer).unwrap();
        self.pro_tx_hash.consensus_encode(&mut writer).unwrap();
        self.time.consensus_encode(&mut writer).unwrap();
        self.ready.consensus_encode(&mut writer).unwrap();
        sha256d::Hash::hash(&writer)
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
        let pro_tx_hash = <[u8; 32]>::consensus_decode(d)?;
        let time = i64::consensus_decode(d)?;
        let ready: bool = bool::consensus_decode(d)?;
        let _signature_len = VarInt::consensus_decode(d)?;
        let signature: Option<[u8; 96]> = <[u8; 96]>::consensus_decode(d).ok();
        let message = CoinJoinQueueMessage { denomination, pro_tx_hash, time, ready, signature, tried: false };
        Ok(message)
    }
}