use std::io;
use std::io::{Read, Write};
use dashcore::consensus::{Decodable, Encodable, encode::Error};
use dashcore::TxIn;
use crate::messages::coinjoin_message::CoinJoinMessageType;

// dss
// #[repr(C)]
#[derive(Clone, Debug)]
pub struct CoinJoinSignedInputs {
    pub inputs: Vec<TxIn>,
}

impl CoinJoinMessageType for CoinJoinSignedInputs {
    fn get_message_type(&self) -> String {
        return "dss".to_string();
    }
}

impl std::fmt::Display for CoinJoinSignedInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoinJoinSignedInputs {{ inputs: [")?;
        for (i, input) in self.inputs.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{{ input_hash: {}, index: {} }}", input.previous_output, input.previous_output.vout)?;
        }
        write!(f, "] }}")
    }
}

impl Encodable for CoinJoinSignedInputs {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.inputs.consensus_encode(writer)?;
        // let mut offset = 0;
        // let amount = VarInt(self.inputs.len() as u64);
        // offset += amount.consensus_encode(&mut writer)?;
        //
        // for i in 0..self.inputs.len() {
        //     offset += self.inputs[i].consensus_encode(&mut writer)?;
        // }
        //
        Ok(offset)
    }
}

impl Decodable for CoinJoinSignedInputs {
    #[inline]
    fn consensus_decode<D: Read + ?Sized>(d: &mut D) -> Result<Self, Error> {
        let inputs = <Vec<TxIn>>::consensus_decode(d)?;
        Ok(CoinJoinSignedInputs { inputs })
    }
}
