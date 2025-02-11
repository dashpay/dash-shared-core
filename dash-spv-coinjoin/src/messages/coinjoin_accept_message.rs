use std::io::{Read, Write, Error};
use dash_spv_masternode_processor::consensus::encode;
use dash_spv_masternode_processor::tx::transaction::{Transaction, TransactionType};
use crate::coinjoin::CoinJoin;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dsa
#[repr(C)]
#[derive(Clone, Debug)]
pub struct CoinJoinAcceptMessage {
    pub denomination: u32,
    pub tx_collateral: Transaction,
}

impl std::fmt::Display for CoinJoinAcceptMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        
        write!(f, "CoinJoinAccept(denom={}[{}], txCol={:?})",
            CoinJoin::denomination_to_string(self.denomination),
            self.denomination,
            self.tx_collateral.tx_hash
        )?;
        Ok(())
    }
}


impl CoinJoinAcceptMessage {
    pub fn new(denomination: u32, tx_collateral: Transaction) -> Self {
        return Self {
            denomination,
            tx_collateral
        };
    }
}

impl CoinJoinMessageType for CoinJoinAcceptMessage {
    fn get_message_type(&self) -> String {
        return "dsa".to_string();
    }
}

impl encode::Encodable for CoinJoinAcceptMessage {
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

impl encode::Decodable for CoinJoinAcceptMessage {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let denomination = u32::consensus_decode(&mut d)?;
        let mut tx_collateral = Transaction::consensus_decode(&mut d)?;
        tx_collateral.tx_type = TransactionType::Classic;

        Ok(CoinJoinAcceptMessage { denomination, tx_collateral })
    }
}
