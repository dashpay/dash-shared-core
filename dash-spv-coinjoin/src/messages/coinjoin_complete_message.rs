use std::io::{Read, Write, Error};
use dash_spv_masternode_processor::consensus::encode;
use crate::messages::pool_message::PoolMessage;

// dsc
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinCompleteMessage {
    pub msg_session_id: i32,
    pub msg_message_id: PoolMessage,
}

impl encode::Encodable for CoinJoinCompleteMessage {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.msg_session_id.consensus_encode(&mut writer)?;
        offset += self.msg_message_id.value().consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinCompleteMessage {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let msg_session_id = u32::consensus_decode(&mut d)? as i32;
        let message_id = u32::consensus_decode(&mut d)? as i32;

        Ok(CoinJoinCompleteMessage {
            msg_session_id,
            msg_message_id: PoolMessage::from_value(message_id)
        })
    }
}
