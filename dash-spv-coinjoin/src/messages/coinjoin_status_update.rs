use std::io;
use std::io::{Error, Write};
use dash_spv_masternode_processor::consensus::{Decodable, Encodable, encode};

use super::pool_message::PoolMessage;
use super::pool_state::PoolState;
use super::pool_status_update::PoolStatusUpdate;

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

impl Encodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += (self.session_id as u32).consensus_encode(&mut writer)?;
        offset += (self.pool_state.value() as u32).consensus_encode(&mut writer)?;

        // TODO: versioning
        // if (protocolVersion <= params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.COINJOIN_SU)) {
        //     Utils.uint32ToByteStreamLE(0, stream); // nEntriesCount, deprecated
        // }

        offset += (self.status_update.value() as u32).consensus_encode(&mut writer)?;
        offset += (self.message_id.value() as u32).consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl Decodable for CoinJoinStatusUpdate {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let session_id = u32::consensus_decode(&mut d)? as i32;
        let pool_state = u32::consensus_decode(&mut d)? as i32;

        // TODO: versioning
        // if (protocolVersion <= params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.COINJOIN_SU)) {
        //     cursor += 4; // Skip deprecated nEntriesCount
        // }
        
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
