use std::io;
use std::io::{Error, Write};
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use dashcore::{OutPoint, ScriptBuf, TxIn, Txid};
use dashcore::hashes::Hash;
use hashes::hex::ToHex;
use crate::consensus::{encode, Decodable, Encodable};
use crate::crypto::{UInt256, VarBytes};

#[derive(Clone)]
#[ferment_macro::export]
pub struct TransactionInput {
    pub input_hash: [u8; 32],
    pub index: u32,
    pub script: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub sequence: u32,
}

impl From<TransactionInput> for TxIn {
    fn from(value: TransactionInput) -> Self {
        TxIn {
            previous_output: OutPoint { txid: Txid::from_byte_array(value.input_hash), vout: value.index },
            script_sig: ScriptBuf(value.script.unwrap_or_default()),
            sequence: value.sequence,
            witness: Default::default(),
        }
    }
}

impl std::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("input_hash", &self.input_hash)
            .field("index", &self.index)
            .field(
                "script",
                &self.script.as_ref().unwrap_or(&Vec::<u8>::new()).to_hex(),
            )
            .field(
                "signature",
                &self
                    .signature
                    .as_ref()
                    .unwrap_or(&Vec::<u8>::new())
                    .to_hex(),
            )
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl Encodable for TransactionInput {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        offset += self.input_hash.consensus_encode(&mut writer)?;
        offset += self.index.consensus_encode(&mut writer)?;
        offset += match self.signature {
            Some(ref signature) => signature.consensus_encode(&mut writer)?,
            None => 0
        };
        offset += self.sequence.consensus_encode(&mut writer)?;
        Ok(offset)
    }
}

impl Decodable for TransactionInput {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let input_hash = <[u8; 32]>::consensus_decode(&mut d)?;
        let index = u32::consensus_decode(&mut d)?;
        let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        let sequence = u32::consensus_decode(&mut d)?;
        Ok(Self { input_hash, index, signature, sequence, script: None })
    }
}


impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?.0;
        let index = bytes.read_with::<u32>(offset, LE)?;
        let signature = match bytes.read_with::<VarBytes>(offset, LE) {
            Ok(data) => Some(data.1.to_vec()),
            Err(_err) => None,
        };
        let sequence = bytes.read_with::<u32>(offset, LE)?;
        let input = TransactionInput {
            input_hash,
            index,
            script: None,
            signature,
            sequence,
        };
        Ok((input, *offset))
    }
}
