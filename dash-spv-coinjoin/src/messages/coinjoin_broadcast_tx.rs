use std::io;
use std::io::{Cursor, Read, Write};
use dashcore::consensus::{Decodable, Encodable};
use dashcore::consensus::encode::Error;
use dashcore::Transaction;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dstx
// #[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinBroadcastTx {
    pub tx: Transaction,
    pub pro_tx_hash: [u8; 32],
    pub signature: Option<Vec<u8>>,
    pub signature_time: i64,
    // memory only
    // when corresponding tx is 0-confirmed or conflicted, nConfirmedHeight is -1
    pub confirmed_height: i32,
}

#[ferment_macro::export]
pub fn from_message(message: &[u8]) -> CoinJoinBroadcastTx {
    let mut cursor = Cursor::new(message);
    CoinJoinBroadcastTx::consensus_decode(&mut cursor).unwrap()
}

impl CoinJoinBroadcastTx {
    pub fn new(tx: Transaction, pro_tx_hash: [u8; 32], signature: Option<Vec<u8>>, signature_time: i64) -> Self {
        Self {
            tx,
            pro_tx_hash,
            signature,
            signature_time,
            confirmed_height: -1,
        }
    }

    pub fn set_confirmed_height(&mut self, confirmed_height: i32) {
        self.confirmed_height = confirmed_height;
    }

}

impl CoinJoinMessageType for CoinJoinBroadcastTx {
    fn get_message_type(&self) -> String {
        return "dstx".to_string();
    }
}

impl Encodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.tx.consensus_encode(writer)?;
        // let tx_data = self.tx.to_data(); // TODO: consensus_encode
        // writer.write_all(&tx_data)?;
        // offset += self.tx.consensus_encode(&mut writer)?;
        // offset += tx_data.len();
        offset += self.pro_tx_hash.consensus_encode(writer)?;
        offset += match self.signature {
            Some(ref signature) => signature.consensus_encode(writer)?,
            None => 0
        };
        offset += self.signature_time.consensus_encode(writer)?;

        Ok(offset)
    }
}

impl Decodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let tx = Transaction::consensus_decode(d)?;
        let pro_tx_hash = <[u8; 32]>::consensus_decode(d)?;
        let signature: Option<Vec<u8>> = Vec::consensus_decode(d).ok();
        let signature_time = i64::consensus_decode(d)?;

        Ok(CoinJoinBroadcastTx::new(tx, pro_tx_hash, signature, signature_time) )
    }
}
