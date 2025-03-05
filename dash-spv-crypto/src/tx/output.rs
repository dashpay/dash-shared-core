use std::io;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dashcore::{ScriptBuf, TxOut};
use dashcore::consensus::{Decodable, Encodable};
use dashcore::secp256k1::hashes::hex::DisplayHex;
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
            .field("script", &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_lower_hex_string())
            .field("address", &self.address.as_ref().unwrap_or(&Vec::<u8>::new()).to_lower_hex_string())
            .finish()
    }
}

impl Encodable for TransactionOutput {
    #[inline]
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut offset = 0;
        offset += self.amount.consensus_encode(writer)?;
        offset += match self.script {
            Some(ref script) => script.consensus_encode(writer)?,
            None => 0
        };
        Ok(offset)
    }
}

impl Decodable for TransactionOutput {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, dashcore::consensus::encode::Error> {
        let amount = u64::consensus_decode(reader)?;
        let script: Option<Vec<u8>> = Vec::consensus_decode(reader).ok();
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