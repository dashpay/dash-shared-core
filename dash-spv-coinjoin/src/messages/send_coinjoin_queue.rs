use std::io;
use std::io::{Error, Write};
use dash_spv_masternode_processor::consensus::{Decodable, Encodable, encode};

// senddsq
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SendCoinJoinQueue {
    pub send: bool,
}

impl Encodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.send.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl Decodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let send = bool::consensus_decode(&mut d)?;

        Ok(SendCoinJoinQueue { send })
    }
}
