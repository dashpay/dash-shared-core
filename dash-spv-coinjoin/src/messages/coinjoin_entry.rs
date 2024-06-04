use std::io::{Read, Write, Error};
use dash_spv_masternode_processor::consensus::encode;
use dash_spv_masternode_processor::tx::transaction::{TransactionInput, TransactionOutput, Transaction, TransactionType};
use dash_spv_masternode_processor::consensus::encode::VarInt;
use crate::messages::coinjoin_message::CoinJoinMessage;

// dsi
// A client's transaction in the mixing pool
// #[repr(C)]
#[derive(Clone, Debug)]
// #[ferment_macro::export]
pub struct CoinJoinEntry {
    pub mixing_inputs: Vec<TransactionInput>,
    pub mixing_outputs: Vec<TransactionOutput>,
    pub tx_collateral: Transaction,
}

impl CoinJoinMessage for CoinJoinEntry {
    fn get_message_type(&self) -> String {
        return "dsi".to_string();
    }
}

impl encode::Encodable for CoinJoinEntry {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        let inputs_amount = VarInt(self.mixing_inputs.len() as u64);
        offset += inputs_amount.consensus_encode(&mut writer)?;

        for i in 0..self.mixing_inputs.len() {
            offset += self.mixing_inputs[i].consensus_encode(&mut writer)?;   
        }

        let tx_data = self.tx_collateral.to_data(); // TODO: consensus_encode
        writer.write_all(&tx_data)?;
        offset += tx_data.len();

        let outputs_amount = VarInt(self.mixing_outputs.len() as u64);
        offset += outputs_amount.consensus_encode(&mut writer)?;

        for i in 0..self.mixing_outputs.len() {
            offset += self.mixing_outputs[i].consensus_encode(&mut writer)?;   
        }

        Ok(offset)
    }
}

impl encode::Decodable for CoinJoinEntry {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, encode::Error> {
        let mut mixing_inputs = vec![];
        let input_amount = encode::VarInt::consensus_decode(&mut d)?.0;

        for _ in 0..input_amount {
            let input = TransactionInput::consensus_decode(&mut d)?;
            mixing_inputs.push(input);
        }

        let mut tx_collateral = Transaction::consensus_decode(&mut d)?;
        tx_collateral.tx_type = TransactionType::Classic;

        let mut mixing_outputs = vec![];
        let output_amount = encode::VarInt::consensus_decode(&mut d)?.0;

        for _ in 0..output_amount {
            let output = TransactionOutput::consensus_decode(&mut d)?;
            mixing_outputs.push(output);
        }

        Ok(CoinJoinEntry { 
            mixing_inputs,
            tx_collateral,
            mixing_outputs
         })
    }
}
