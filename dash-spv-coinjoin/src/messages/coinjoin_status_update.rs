use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::consensus::encode;

use crate::messages::pool_message::PoolMessage;
use crate::messages::pool_state::PoolState;
use crate::messages::pool_status_update::PoolStatusUpdate;
use crate::messages::coinjoin_message::CoinJoinMessage;

// dssu
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinStatusUpdate {
    pub session_id: i32,
    pub pool_state: PoolState,
    pub status_update: PoolStatusUpdate,
    pub message_id: PoolMessage,
}

impl CoinJoinMessage for CoinJoinStatusUpdate {
    fn get_message_type(&self) -> String {
        return "dssu".to_string();
    }
}

impl encode::Encodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += (self.session_id as u32).consensus_encode(&mut writer)?;
        offset += (self.pool_state.value() as u32).consensus_encode(&mut writer)?;
        offset += (self.status_update.value() as u32).consensus_encode(&mut writer)?;
        offset += (self.message_id.value() as u32).consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let session_id = u32::consensus_decode(&mut d)? as i32;
        let pool_state = u32::consensus_decode(&mut d)? as i32;
        let status_update = u32::consensus_decode(&mut d)? as i32;
        let message_id = u32::consensus_decode(&mut d)? as i32;

        Ok(CoinJoinStatusUpdate {
            session_id,
            pool_state: PoolState::from_value(pool_state),
            status_update: PoolStatusUpdate::from_value(status_update),
            message_id: PoolMessage::from_value(message_id)
        })
    }
}
