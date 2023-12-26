use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use dash_spv_masternode_processor::consensus::encode;

// dsq
// A currently in progress mixing merge and denomination information
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinQueueMessage {
    pub denomination: u32,
    pub pro_tx_hash: UInt256,
    pub time: i64,
    pub ready: bool, // ready to submit
    pub signature: Option<Vec<u8>>,
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
        let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        
        Ok(CoinJoinQueueMessage { denomination, pro_tx_hash, time, ready, signature })
    }
}
