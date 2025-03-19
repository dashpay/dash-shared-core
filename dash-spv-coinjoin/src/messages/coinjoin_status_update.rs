use std::io;
use std::io::{Cursor, Read, Write};
use dashcore::consensus::{Decodable, Encodable};
use dashcore::consensus::encode::Error;
use crate::messages::pool_message::PoolMessage;
use crate::messages::pool_state::PoolState;
use crate::messages::pool_status_update::PoolStatusUpdate;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dssu
// #[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinStatusUpdate {
    pub session_id: i32,
    pub pool_state: PoolState,
    pub status_update: PoolStatusUpdate,
    pub message_id: PoolMessage,
}

#[ferment_macro::export]
pub fn from_message(message: &[u8]) -> CoinJoinStatusUpdate {
    let mut cursor = Cursor::new(message);
    CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap()
}

impl CoinJoinMessageType for CoinJoinStatusUpdate {
    fn get_message_type(&self) -> String {
        "dssu".to_string()
    }
}

impl Encodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += (self.session_id as u32).consensus_encode(writer)?;
        offset += (self.pool_state.value() as u32).consensus_encode(writer)?;
        offset += (self.status_update.value() as u32).consensus_encode(writer)?;
        offset += (self.message_id.value() as u32).consensus_encode(writer)?;

        Ok(offset)
    }
}

impl Decodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let session_id = u32::consensus_decode(d)? as i32;
        let pool_state = u32::consensus_decode(d)? as i32;
        let status_update = u32::consensus_decode(d)? as i32;
        let message_id = u32::consensus_decode(d)? as i32;

        Ok(CoinJoinStatusUpdate {
            session_id,
            pool_state: PoolState::from_value(pool_state),
            status_update: PoolStatusUpdate::from_value(status_update),
            message_id: PoolMessage::from_value(message_id)
        })
    }
}
