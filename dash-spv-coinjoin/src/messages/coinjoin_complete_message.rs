use std::io;
use std::io::{Cursor, Read, Write};
use dashcore::consensus::{Decodable, Encodable, encode::Error};
use crate::messages::pool_message::PoolMessage;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsc
// #[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinCompleteMessage {
    pub msg_session_id: i32,
    pub msg_message_id: PoolMessage,
}

#[ferment_macro::export]
pub fn from_message(message: &[u8]) -> CoinJoinCompleteMessage {
    let mut cursor = Cursor::new(message);
    CoinJoinCompleteMessage::consensus_decode(&mut cursor).unwrap()
}

impl CoinJoinMessageType for CoinJoinCompleteMessage {
    fn get_message_type(&self) -> String {
        "dsc".to_string()
    }
}

impl Encodable for CoinJoinCompleteMessage {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.msg_session_id.consensus_encode(writer)?;
        offset += self.msg_message_id.value().consensus_encode(writer)?;

        Ok(offset)
    }
}

impl Decodable for CoinJoinCompleteMessage {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let msg_session_id = u32::consensus_decode(d)? as i32;
        let message_id = u32::consensus_decode(d)? as i32;

        Ok(CoinJoinCompleteMessage {
            msg_session_id,
            msg_message_id: PoolMessage::from_value(message_id)
        })
    }
}
