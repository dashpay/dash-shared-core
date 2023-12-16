use std::io;
use std::io::{Error, Write};
use dash_spv_masternode_processor::tx::{Transaction, TransactionType::Classic};
use dash_spv_masternode_processor::consensus::{Decodable, Encodable, encode};

// dsf
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinFinalTransaction {
    pub msg_session_id: i32,
    pub tx: Transaction,
}

impl Encodable for CoinJoinFinalTransaction {
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

impl Decodable for CoinJoinFinalTransaction {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let msg_session_id = u32::consensus_decode(&mut d)? as i32;
        let mut tx = Transaction::consensus_decode(&mut d)?;
        tx.tx_type = Classic;

        Ok(CoinJoinFinalTransaction { msg_session_id, tx })
    }
}
