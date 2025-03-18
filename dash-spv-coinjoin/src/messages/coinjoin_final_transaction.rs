use std::io;
use std::io::{Read, Write};
use dashcore::consensus::{Decodable, Encodable, encode::Error};
use dashcore::Transaction;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsf
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CoinJoinFinalTransaction {
    pub msg_session_id: i32,
    pub tx: Transaction,
}

impl CoinJoinMessageType for CoinJoinFinalTransaction {
    fn get_message_type(&self) -> String {
        "dsf".to_string()
    }
}

impl Encodable for CoinJoinFinalTransaction {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += (self.msg_session_id as u32).consensus_encode(writer)?;
        offset += self.tx.consensus_encode(writer)?;
        // let tx_data = self.tx.to_data(); // TODO: consensus_encode
        // writer.write_all(&tx_data)?;
        // offset += tx_data.len();

        Ok(offset)
    }
}

impl Decodable for CoinJoinFinalTransaction {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let msg_session_id = u32::consensus_decode(d)? as i32;
        let tx = Transaction::consensus_decode(d)?;
        // tx.tx_type = TransactionType::Classic;

        Ok(CoinJoinFinalTransaction { msg_session_id, tx })
    }
}
