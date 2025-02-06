use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::crypto::byte_util::{Reversable, UInt256};
use dash_spv_masternode_processor::consensus::encode;

#[derive(Clone, Eq, PartialEq, Hash)]
pub struct TxOutPoint {
    pub hash: UInt256,
    pub index: u32,
}

impl std::fmt::Debug for TxOutPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TxOutPoint")
            .field("hash", &self.hash.reversed())
            .field("index", &self.index)
            .finish()
    }
}

impl TxOutPoint {
    pub fn new(hash: UInt256, index: u32) -> Self {
        TxOutPoint { hash, index }
    }
}

impl encode::Encodable for TxOutPoint {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.hash.consensus_encode(&mut writer)?;
        offset += self.index.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for TxOutPoint {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let hash = UInt256::consensus_decode(&mut d)?;
        let index = u32::consensus_decode(&mut d)?;

        Ok(TxOutPoint { hash, index })
    }
}
