use std::io;
use std::io::{Cursor, Read, Write};
use dashcore::consensus::{Decodable, Encodable, encode::Error};
use dashcore::blockdata::transaction::Transaction;
use crate::coinjoin::CoinJoin;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsa
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinAcceptMessage {
    pub denomination: u32,
    pub tx_collateral: Transaction,
}
#[ferment_macro::export]
pub fn from_message(message: &[u8]) -> CoinJoinAcceptMessage {
    let mut cursor = Cursor::new(message);
    CoinJoinAcceptMessage::consensus_decode(&mut cursor).unwrap()
}
impl std::fmt::Display for CoinJoinAcceptMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        
        write!(f, "CoinJoinAccept(denom={}[{}], txCol={:?})",
            CoinJoin::denomination_to_string(self.denomination),
            self.denomination,
            self.tx_collateral.txid().to_hex()
        )?;
        Ok(())
    }
}


impl CoinJoinAcceptMessage {
    pub fn new(denomination: u32, tx_collateral: Transaction) -> Self {
        Self {
            denomination,
            tx_collateral
        }
    }
}

impl CoinJoinMessageType for CoinJoinAcceptMessage {
    fn get_message_type(&self) -> String {
        return "dsa".to_string();
    }
}

impl Encodable for CoinJoinAcceptMessage {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.denomination.consensus_encode(writer)?;
        offset += self.tx_collateral.consensus_encode(writer)?;
        // TODO: consensus_encode
        // writer.write_all(&tx_data)?;
        // offset += tx_data.len();

        Ok(offset)
    }
}

impl Decodable for CoinJoinAcceptMessage {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let denomination = u32::consensus_decode(d)?;
        let tx_collateral = Transaction::consensus_decode(d)?;
        // tx_collateral.tx_type = TransactionType::Classic;

        Ok(CoinJoinAcceptMessage { denomination, tx_collateral })
    }
}
