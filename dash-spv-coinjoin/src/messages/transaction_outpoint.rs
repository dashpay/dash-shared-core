use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::crypto::byte_util::UInt256;
use dash_spv_masternode_processor::consensus::encode;

#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransactionOutPoint {
    pub hash: UInt256,
    pub index: u32,
}

impl encode::Encodable for TransactionOutPoint {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.hash.consensus_encode(&mut writer)?;
        offset += self.index.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for TransactionOutPoint {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let hash = UInt256::consensus_decode(&mut d)?;
        let index = u32::consensus_decode(&mut d)?;

        Ok(TransactionOutPoint { hash, index })
    }
}
