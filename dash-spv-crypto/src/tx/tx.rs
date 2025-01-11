use std::io;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use hashes::{sha256d, Hash};
use crate::consensus::{Decodable, Encodable, encode, encode::VarInt};
use crate::crypto::byte_util::UInt256;
use crate::network::protocol::SIGHASH_ALL;
use crate::tx::{TransactionInput, TransactionOutput};
use crate::util::params::TX_UNCONFIRMED;

#[repr(C)]
#[derive(Clone, Debug, PartialEq)]
#[ferment_macro::export]
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
        u16::from(self.clone())
    }
    pub fn requires_inputs(&self) -> bool {
        true
    }

    pub fn is_classic(&self) -> bool {
        if &TransactionType::Classic == self {
            true
        } else {
            false
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

#[derive(Debug, Clone)]
#[ferment_macro::export]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>,
    pub lock_time: u32,
    pub version: u16,
    pub tx_hash: Option<[u8; 32]>,
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
            self.tx_type.clone(),
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
        *offset += version.enc(&mut buffer);
        *offset += tx_type.raw_value().enc(&mut buffer);
        *offset += VarInt(inputs_len as u64)
            .enc(&mut buffer);
        (0..inputs_len).into_iter().for_each(|i| {
            let input = &inputs[i];
            *offset += input.input_hash.enc(&mut buffer);
            *offset += input.index.enc(&mut buffer);
            if subscript_index == u64::MAX && input.signature.is_some() {
                *offset += input
                    .signature
                    .as_ref()
                    .unwrap()
                    .enc(&mut buffer);
                // *offset += consensus_encode_with_size(input.signature.unwrap(), &mut buffer).unwrap()
            } else if subscript_index == i as u64 && input.script.is_some() {
                *offset += input
                    .script
                    .as_ref()
                    .unwrap()
                    .enc(&mut buffer);
                // *offset += consensus_encode_with_size(input.script.unwrap(), &mut buffer).unwrap()
            } else {
                *offset += VarInt(0_u64).enc(&mut buffer);
            }
            *offset += input.sequence.enc(&mut buffer);
        });
        *offset += VarInt(outputs_len as u64).enc(&mut buffer);
        (0..outputs_len).into_iter().for_each(|i| {
            let output = &outputs[i];
            *offset += output.amount.enc(&mut buffer);
            if let Some(script) = &output.script {
                *offset += script.enc(&mut buffer);
                //*offset += consensus_encode_with_size(script, &mut buffer).unwrap()
            }
        });
        *offset += lock_time.enc(&mut buffer);
        if subscript_index != u64::MAX {
            *offset += SIGHASH_ALL.enc(&mut buffer);
        }
        buffer
    }

    pub fn input_addresses(&self) -> Vec<Vec<u8>> {
        // TODO: implement this after transactions migration from DashSync
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

    pub fn tx_hash(&self) -> Option<[u8; 32]> {
        self.tx_hash
    }

    pub fn tx_type(&self) -> TransactionType {
        self.tx_type.clone()
    }
}

impl Decodable for Transaction {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = u16::consensus_decode(&mut d)?;
        let tx_type = TransactionType::consensus_decode(&mut d)?;
        let is_classic = tx_type.is_classic();
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
        tx.tx_hash = is_classic.then(|| sha256d::Hash::hash(&tx.to_data()).into_inner());
        Ok(tx)
    }
}

impl<'a> TryRead<'a, Endian> for Transaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<u16>(offset, endian)?;
        let tx_type_uint = bytes.read_with::<u16>(offset, endian)?;
        let tx_type = TransactionType::from(tx_type_uint);
        let is_classic = tx_type.is_classic();
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
        tx.tx_hash = is_classic.then(|| sha256d::Hash::hash(tx.to_data().as_ref()).into_inner());
        Ok((tx, *offset))
    }
}

