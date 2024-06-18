use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::tx::transaction::{Transaction, TransactionType};
use dash_spv_masternode_processor::consensus::encode;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsf
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinFinalTransaction {
    pub msg_session_id: i32,
    pub tx: Transaction,
}

impl CoinJoinMessageType for CoinJoinFinalTransaction {
    fn get_message_type(&self) -> String {
        return "dsf".to_string();
    }
}

impl encode::Encodable for CoinJoinFinalTransaction {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += (self.msg_session_id as u32).consensus_encode(&mut writer)?;
        let tx_data = self.tx.to_data(); // TODO: consensus_encode
        writer.write_all(&tx_data)?;
        offset += tx_data.len();

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinFinalTransaction {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let msg_session_id = u32::consensus_decode(&mut d)? as i32;
        let mut tx = Transaction::consensus_decode(&mut d)?;
        tx.tx_type = TransactionType::Classic;

        Ok(CoinJoinFinalTransaction { msg_session_id, tx })
    }
}
