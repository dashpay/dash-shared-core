use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::consensus::encode;

// senddsq
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SendCoinJoinQueue {
    pub send: bool,
}

impl encode::Encodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.send.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let send = bool::consensus_decode(&mut d)?;

        Ok(SendCoinJoinQueue { send })
    }
}
