use std::io::{Error, Read, Write};
use dashcore::consensus::{encode, Decodable, Encodable};
use crate::messages::coinjoin_message::CoinJoinMessageType;

// senddsq
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct SendCoinJoinQueue {
    pub send: bool,
}

impl CoinJoinMessageType for SendCoinJoinQueue {
    fn get_message_type(&self) -> String {
        return "senddsq".to_string();
    }
}

impl Encodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.send.consensus_encode(writer)?;

        Ok(offset)
    }
}

impl Decodable for SendCoinJoinQueue {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, encode::Error> {
        let send = bool::consensus_decode(d)?;

        Ok(SendCoinJoinQueue { send })
    }
}
