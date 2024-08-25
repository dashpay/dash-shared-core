use std::io;

use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use hashes::hex::ToHex;
use crate::blockdata::opcodes::all::OP_RETURN;
use crate::consensus::encode::{VarInt, self};
use crate::consensus::{Encodable, Decodable};
use crate::crypto::{UInt256, VarBytes};
use crate::util::data_append::DataAppend;
use crate::util::script::{ScriptType, ScriptElement};

// block height indicating transaction is unconfirmed
pub const TX_UNCONFIRMED: i32 = i32::MAX;

pub static SIGHASH_ALL: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum TransactionType {
    Classic = 0,
    ProviderRegistration = 1,
    ProviderUpdateService = 2,
    ProviderUpdateRegistrar = 3,
    ProviderUpdateRevocation = 4,
    Coinbase = 5,
    QuorumCommitment = 6,
    AssetLock = 8,
    AssetUnlock = 9,
    TypeMax = 10,
    SubscriptionCloseAccount = 11,
    Transition = 12,
    // tmp
    /// TODO: find actual value for this type
    CreditFunding = 255,
}

impl Decodable for TransactionType {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(TransactionType::from(u16::consensus_decode(&mut d)?))
    }
}

impl From<u16> for TransactionType {
    fn from(orig: u16) -> Self {
        match orig {
            0x0000 => TransactionType::Classic,
            0x0001 => TransactionType::ProviderRegistration,
            0x0002 => TransactionType::ProviderUpdateService,
            0x0003 => TransactionType::ProviderUpdateRegistrar,
            0x0004 => TransactionType::ProviderUpdateRevocation,
            0x0005 => TransactionType::Coinbase,
            0x0006 => TransactionType::QuorumCommitment,
            0x0008 => TransactionType::AssetLock,
            0x0009 => TransactionType::AssetUnlock,
            0x000A => TransactionType::TypeMax,
            0x000B => TransactionType::SubscriptionCloseAccount,
            0x000C => TransactionType::Transition,
            _ => TransactionType::Classic,
        }
    }
}

impl From<TransactionType> for u16 {
    fn from(value: TransactionType) -> Self {
        value as u16
    }
}

impl TransactionType {
    fn raw_value(&self) -> u16 {
        *self as u16
    }
    pub fn requires_inputs(&self) -> bool {
        true
    }
}

#[derive(Clone, PartialEq)]
pub struct TransactionInput {
    pub input_hash: UInt256,
    pub index: u32,
    pub script: Option<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
    pub sequence: u32,
}

impl Encodable for TransactionInput {
    #[inline]
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
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
        let input_hash = UInt256::consensus_decode(&mut d)?;
        let index = u32::consensus_decode(&mut d)?;
        let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        let sequence = u32::consensus_decode(&mut d)?;
        Ok(Self { input_hash, index, signature, sequence, script: None })
    }
}


impl std::fmt::Debug for TransactionInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionInput")
            .field("input_hash", &self.input_hash)
            .field("index", &self.index)
            .field(
                "script",
                &self.script.as_ref().map_or("None".to_string(), |s| s.to_hex()),
            )
            .field(
                "signature",
                &self.signature.as_ref().map_or("None".to_string(), |s| s.to_hex()),
            )
            .field("sequence", &self.sequence)
            .finish()
    }
}

impl<'a> TryRead<'a, Endian> for TransactionInput {
    fn try_read(bytes: &'a [u8], _endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let input_hash = bytes.read_with::<UInt256>(offset, LE)?;
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

#[derive(Clone, PartialEq)]
pub struct TransactionOutput {
    pub amount: u64,
    pub script: Option<Vec<u8>>,
    pub address: Option<Vec<u8>>,
}

impl Encodable for TransactionOutput {
    #[inline]
    fn consensus_encode<W: io::Write>(&self, mut writer: W) -> Result<usize, io::Error> {
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

impl std::fmt::Debug for TransactionOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionOutput")
            .field("amount", &self.amount)
            .field("script", &self.script.as_ref().map_or("None".to_string(), |s| s.to_hex()))
            .field("address", &self.address.as_ref().map_or("None".to_string(), |s| s.to_hex()))
            .finish()
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

impl TransactionOutput {
    const MAX_SCRIPT_SIZE: usize = 10000;
    
    pub fn script_pub_key_type(&self) -> ScriptType {
        if let Some(ref script) = self.script {
            match script.script_elements()[..] {
                // pay-to-pubkey-hash scriptPubKey
                [ScriptElement::Number(0x76/*OP_DUP*/), ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x88/*OP_EQUALVERIFY*/), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
                    ScriptType::PayToPubkeyHash,
                // pay-to-script-hash scriptPubKey
                [ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x87/*OP_EQUAL*/)] =>
                    ScriptType::PayToScriptHash,
                // pay-to-pubkey scriptPubKey
                [ScriptElement::Data(data, len @ 33u8 | len @ 65u8), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
                    ScriptType::PayToPubkey,
                // unknown script type
                _ => ScriptType::Unknown,
            }
        } else {
            return ScriptType::Unknown;
        }
    }

    /// Returns whether the script is guaranteed to fail at execution,
    /// regardless of the initial stack. This allows outputs to be pruned
    /// instantly when entering the UTXO set.
    pub fn is_script_unspendable(&self) -> bool {
        if let Some(ref script) = self.script {
            let script_elements = script.script_elements();

            return script_elements.len() > 0 && script_elements[0] == ScriptElement::Number(OP_RETURN.into_u8()) ||
                   script.len() > Self::MAX_SCRIPT_SIZE;
        } else {
            return true;
        }
    }
}

pub trait ITransaction {
    fn payload_data(&self) -> Vec<u8>;
    fn payload_data_for(&self) -> Vec<u8>;
    fn transaction_type(&self) -> TransactionType;
    fn outputs(&self) -> Vec<TransactionOutput>;
    fn output_addresses(&self) -> Vec<Vec<u8>>;
    fn inputs(&self) -> Vec<TransactionInput>;
    fn tx_hash(&self) -> Option<UInt256>;
    fn tx_type(&self) -> TransactionType;
}

#[derive(Debug, Clone, PartialEq)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    pub version: u16,
    pub tx_hash: Option<UInt256>,
    pub tx_type: TransactionType,
    pub payload_offset: usize,
    pub block_height: u32,
}

impl Transaction {
    pub fn to_data(&self) -> Vec<u8> {
        self.to_data_with_subscript_index(u64::MAX)
    }

    pub fn to_data_with_subscript_index(&self, subscript_index: u64) -> Vec<u8> {
        Self::data_with_subscript_index_static(
            subscript_index,
            self.version,
            self.tx_type,
            &self.inputs,
            &self.outputs,
            self.lock_time,
        )
    }

    pub fn data_with_subscript_index_static(
        subscript_index: u64,
        version: u16,
        tx_type: TransactionType,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        lock_time: u32,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let inputs_len = inputs.len();
        let outputs_len = outputs.len();
        *offset += version.consensus_encode(&mut buffer).unwrap();
        *offset += tx_type.raw_value().consensus_encode(&mut buffer).unwrap();
        *offset += VarInt(inputs_len as u64)
            .consensus_encode(&mut buffer)
            .unwrap();
        (0..inputs_len).into_iter().for_each(|i| {
            let input = &inputs[i];
            *offset += input.input_hash.consensus_encode(&mut buffer).unwrap();
            *offset += input.index.consensus_encode(&mut buffer).unwrap();
            if subscript_index == u64::MAX && input.signature.is_some() {
                *offset += input
                    .signature
                    .as_ref()
                    .unwrap()
                    .consensus_encode(&mut buffer)
                    .unwrap()
                // *offset += consensus_encode_with_size(input.signature.unwrap(), &mut buffer).unwrap()
            } else if subscript_index == i as u64 && input.script.is_some() {
                *offset += input
                    .script
                    .as_ref()
                    .unwrap()
                    .consensus_encode(&mut buffer)
                    .unwrap()
                // *offset += consensus_encode_with_size(input.script.unwrap(), &mut buffer).unwrap()
            } else {
                *offset += VarInt(0_u64).consensus_encode(&mut buffer).unwrap();
            }
            *offset += input.sequence.consensus_encode(&mut buffer).unwrap();
        });
        *offset += VarInt(outputs_len as u64)
            .consensus_encode(&mut buffer)
            .unwrap();
        (0..outputs_len).into_iter().for_each(|i| {
            let output = &outputs[i];
            *offset += output.amount.consensus_encode(&mut buffer).unwrap();
            if let Some(script) = &output.script {
                *offset += script.consensus_encode(&mut buffer).unwrap()
                //*offset += consensus_encode_with_size(script, &mut buffer).unwrap()
            }
        });
        *offset += lock_time.consensus_encode(&mut buffer).unwrap();
        if subscript_index != u64::MAX {
            *offset += SIGHASH_ALL.consensus_encode(&mut buffer).unwrap();
        }
        buffer
    }

    pub fn input_addresses(&self) -> Vec<Vec<u8>> {
        /*let script_map = ScriptMap::MAINNET;
        self.inputs.iter().filter_map(|input| {
            if let Some(script) = &input.script {
                with_script_pub_key(&script, &script_map)
            } else if let Some(signature) = &input.signature {
                with_script_sig(&signature, &script_map)
            } else {
                None
            }
        }).collect()*/
        vec![]
    }

    pub fn output_addresses(&self) -> Vec<Vec<u8>> {
        self.outputs.iter().filter_map(|output| output.address.clone()).collect()
    }

    pub fn outputs(&self) -> Vec<TransactionOutput> {
        self.outputs.clone()
    }

    pub fn inputs(&self) -> Vec<TransactionInput> {
        self.inputs.clone()
    }

    pub fn tx_hash(&self) -> Option<UInt256> {
        self.tx_hash
    }

    pub fn tx_type(&self) -> TransactionType {
        self.tx_type
    }
}

impl Decodable for Transaction {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let tx_type = TransactionType::consensus_decode(&mut d)?;
        let inputs: Vec<TransactionInput> = Vec::consensus_decode(&mut d)?;
        let outputs: Vec<TransactionOutput> = Vec::consensus_decode(&mut d)?;
        let lock_time = u32::consensus_decode(&mut d)?;
        let mut tx = Self {
            inputs,
            outputs,
            version,
            tx_type,
            lock_time,
            block_height: TX_UNCONFIRMED as u32,
            tx_hash: None,
            payload_offset: 0,
        };
        tx.tx_hash = (tx_type == TransactionType::Classic).then_some(UInt256::sha256d(tx.to_data()));
        Ok(tx)
    }
}

impl<'a> TryRead<'a, Endian> for Transaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<u16>(offset, endian)?;
        let tx_type_uint = bytes.read_with::<u16>(offset, endian)?;
        let tx_type = TransactionType::from(tx_type_uint);
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        // at least one input is required
        if count == 0 && tx_type.requires_inputs() {
            return Err(byte::Error::Incomplete);
        }
        let mut inputs: Vec<TransactionInput> = Vec::new();
        for _i in 0..count {
            inputs.push(bytes.read_with::<TransactionInput>(offset, endian)?);
        }
        let mut outputs: Vec<TransactionOutput> = Vec::new();
        let count_var = bytes.read_with::<VarInt>(offset, endian)?;
        let count = count_var.0;
        for _i in 0..count {
            outputs.push(bytes.read_with::<TransactionOutput>(offset, endian)?);
        }
        let lock_time = bytes.read_with::<u32>(offset, endian)?;
        let mut tx = Self {
            inputs,
            outputs,
            version,
            tx_type,
            lock_time,
            payload_offset: *offset,
            tx_hash: None,
            block_height: TX_UNCONFIRMED as u32,
        };
        tx.tx_hash = (tx_type == TransactionType::Classic).then_some(UInt256::sha256d(tx.to_data()));
        Ok((tx, *offset))
    }
}
