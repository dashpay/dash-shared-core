use std::io;
use std::io::{Error, Write};
use dash_spv_masternode_processor::tx::{Transaction, TransactionType::Classic};
use dash_spv_masternode_processor::consensus::{Decodable, Encodable, encode};

// dsa
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinAcceptMessage {
    pub denomination: u32,
    pub tx_collateral: Transaction,
}

impl Encodable for CoinJoinAcceptMessage {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.denomination.consensus_encode(&mut writer)?;
        let tx_data = self.tx_collateral.to_data(); // TODO: consensus_encode
        writer.write_all(&tx_data)?;
        offset += tx_data.len();

        Ok(offset)
    }
}

impl Decodable for CoinJoinAcceptMessage {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let denomination = u32::consensus_decode(&mut d)?;
        let mut tx_collateral = Transaction::consensus_decode(&mut d)?;
        tx_collateral.tx_type = Classic;

        Ok(CoinJoinAcceptMessage { denomination, tx_collateral })
    }
}
