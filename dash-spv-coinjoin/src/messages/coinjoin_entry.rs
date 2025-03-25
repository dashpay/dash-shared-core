use std::io;
use std::io::{Cursor, Read, Write};
use dashcore::blockdata::transaction::Transaction;
use dashcore::blockdata::transaction::txin::TxIn;
use dashcore::blockdata::transaction::txout::TxOut;
use dashcore::consensus::{Decodable, Encodable, encode::{Error, VarInt}};
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsi
// A client's transaction in the mixing pool
// #[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinEntry {
    pub mixing_inputs: Vec<TxIn>,
    pub mixing_outputs: Vec<TxOut>,
    pub tx_collateral: Transaction,
}

#[ferment_macro::export]
pub fn from_message(message: &[u8]) -> CoinJoinEntry {
    let mut cursor = Cursor::new(message);
    CoinJoinEntry::consensus_decode(&mut cursor).unwrap()
}

impl CoinJoinMessageType for CoinJoinEntry {
    fn get_message_type(&self) -> String {
        "dsi".to_string()
    }
}

impl Encodable for CoinJoinEntry {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        let inputs_amount = VarInt(self.mixing_inputs.len() as u64);
        offset += inputs_amount.consensus_encode(writer)?;

        for i in 0..self.mixing_inputs.len() {
            offset += self.mixing_inputs[i].consensus_encode(writer)?;
        }
        offset += self.tx_collateral.consensus_encode(writer)?;
        // let tx_data = self.tx_collateral.to_data(); // TODO: consensus_encode
        // writer.write_all(&tx_data)?;
        // offset += tx_data.len();

        let outputs_amount = VarInt(self.mixing_outputs.len() as u64);
        offset += outputs_amount.consensus_encode(writer)?;

        for i in 0..self.mixing_outputs.len() {
            offset += self.mixing_outputs[i].consensus_encode(writer)?;
        }

        Ok(offset)
    }
}

impl Decodable for CoinJoinEntry {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let mixing_inputs = <Vec<TxIn>>::consensus_decode(d)?;
        let tx_collateral = Transaction::consensus_decode(d)?;
        let mixing_outputs = <Vec<TxOut>>::consensus_decode(d)?;

        Ok(CoinJoinEntry { 
            mixing_inputs,
            tx_collateral,
            mixing_outputs
         })
    }
}
