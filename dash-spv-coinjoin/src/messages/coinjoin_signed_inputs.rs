use std::io::{Error, Read, Write};
use dash_spv_masternode_processor::tx::transaction::TransactionInput;
use dash_spv_masternode_processor::consensus::encode;

// dss
// #[repr(C)]
#[derive(Clone, Debug)]
// #[ferment_macro::export]
pub struct CoinJoinSignedInputs {
    pub inputs: Vec<TransactionInput>,
}

impl encode::Encodable for CoinJoinSignedInputs {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        let amount = encode::VarInt(self.inputs.len() as u64);
        offset += amount.consensus_encode(&mut writer)?;

        for i in 0..self.inputs.len() {
            offset += self.inputs[i].consensus_encode(&mut writer)?;   
        }

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinSignedInputs {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let mut inputs = vec![];
        let amount = encode::VarInt::consensus_decode(&mut d)?.0;

        for _ in 0..amount {
            let input = TransactionInput::consensus_decode(&mut d)?;
            inputs.push(input);
        }

        Ok(CoinJoinSignedInputs { inputs })
    }
}
