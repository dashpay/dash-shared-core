use std::io;
use std::io::{Error, Write};
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dashcore::{ScriptBuf, TxOut};
use hashes::hex::ToHex;
use crate::consensus::{encode, Decodable, Encodable};
use crate::crypto::VarBytes;

#[derive(Clone)]
#[ferment_macro::export]
pub struct TransactionOutput {
    pub amount: u64,
    pub script: Option<Vec<u8>>,
    pub address: Option<Vec<u8>>,
}

impl From<TransactionOutput> for TxOut {
    fn from(value: TransactionOutput) -> Self {
        TxOut {
            value: value.amount,
            script_pubkey: ScriptBuf(value.script.unwrap_or_default()),
        }
    }
}

impl std::fmt::Debug for TransactionOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionOutput")
            .field("amount", &self.amount)
            .field("script", &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex())
            .field("address", &self.address.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex())
            .finish()
    }
}

impl Encodable for TransactionOutput {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.amount.consensus_encode(&mut writer)?;
        offset += match self.script {
            Some(ref script) => script.consensus_encode(&mut writer)?,
            None => 0
        };
        Ok(offset)
    }
}

impl Decodable for TransactionOutput {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let amount = u64::consensus_decode(&mut d)?;
        let script: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        Ok(TransactionOutput { amount, script, address: None })
    }
}

impl<'a> TryRead<'a, Endian> for TransactionOutput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let amount = bytes.read_with::<u64>(offset, LE)?;
        let script = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1.to_vec()),
            Err(_err) => None,
        };
        let output = TransactionOutput {
            amount,
            script,
            address: None,
        };
        Ok((output, *offset))
    }
}