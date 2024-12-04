use byte::{BytesExt, LE};
use hashes::hex::ToHex;
use std::collections::{BTreeMap, HashSet};
use dash_spv_crypto::network::{LLMQType, CORE_PROTO_20, CORE_PROTO_BLS_BASIC, CORE_PROTO_DIFF_VERSION_ORDER};
use dash_spv_crypto::consensus::encode::VarInt;
use dash_spv_crypto::crypto::byte_util::{BytesDecodable, Reversed, UInt256, UInt768};
use dash_spv_crypto::llmq::entry::LLMQEntry;
use dash_spv_crypto::tx::CoinbaseTransaction;
use crate::models::MasternodeEntry;
use crate::models::masternode_entry::MasternodeReadContext;
use crate::processing::CoreProvider;

#[derive(Clone)]
pub struct MNListDiff {
    pub base_block_hash: [u8; 32],
    pub block_hash: [u8; 32],
    pub total_transactions: u32,
    pub merkle_hashes: Vec<[u8; 32]>,
    pub merkle_flags: Vec<u8>,
    pub coinbase_transaction: CoinbaseTransaction,
    pub deleted_masternode_hashes: Vec<[u8; 32]>,
    pub added_or_modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry>,
    pub deleted_quorums: BTreeMap<LLMQType, Vec<[u8; 32]>>,
    pub added_quorums: Vec<LLMQEntry>,
    pub base_block_height: u32,
    pub block_height: u32,
    // 0: protocol_version < 70225
    // 1: all pubKeyOperator of all CSimplifiedMNListEntry are serialised using legacy BLS scheme
    // 2: all pubKeyOperator of all CSimplifiedMNListEntry are serialised using basic BLS scheme
    pub version: u16,

    // protocol_version > 70228
    // 19.2 goes with 70228
    // 19.3 goes with 70229?
    // 20.0 goes with 70230+
    // clsig, heights
    pub quorums_cls_sigs: BTreeMap<[u8; 96], HashSet<u16>>,
}

impl std::fmt::Debug for MNListDiff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MNListDiff")
            .field("base_block_hash", &self.base_block_hash)
            .field("block_hash", &self.block_hash)
            .field("total_transactions", &self.total_transactions)
            .field("merkle_hashes", &self.merkle_hashes)
            .field("merkle_flags", &self.merkle_flags.to_hex())
            .field("merkle_flags_count", &self.merkle_flags.len())
            .field("coinbase_transaction", &self.coinbase_transaction)
            .field("deleted_masternode_hashes", &self.deleted_masternode_hashes)
            .field("added_or_modified_masternodes", &self.added_or_modified_masternodes)
            .field("deleted_quorums", &self.deleted_quorums)
            .field("added_quorums", &self.added_quorums)
            .field("base_block_height", &self.base_block_height)
            .field("block_height", &self.block_height)
            .field("version", &self.version)
            .field("quorums_cls_sigs", &self.quorums_cls_sigs)
            .finish()
    }
}

// impl<V> consensus::Decodable for MNListDiff {
//     #[inline]
//     fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
//         let base_block_hash = UInt256::consensus_decode(&mut d)?;
//         let block_hash = UInt256::consensus_decode(&mut d)?;
//         let total_transactions = u32::consensus_decode(&mut d)?;
//         let merkle_hashes: Vec<UInt256> = Vec::consensus_decode(&mut d)?;
//         let merkle_flags: Vec<u8> = Vec::consensus_decode(&mut d)?;
//         let coinbase_transaction = CoinbaseTransaction::consensus_decode(&mut d)?;
//
//         let version = if protocol_version >= CORE_PROTO_BLS_BASIC {
//             // BLS Basic
//             u16::consensus_decode(&mut d)?
//         } else {
//             // BLS Legacy
//             1
//         };
//         let deleted_masternode_hashes: Vec<UInt256> = Vec::consensus_decode(&mut d)?;
//         let added_or_modified_masternodes: Vec<MasternodeEntry> = Vec::consensus_decode(&mut d)?;
//
//         let added_or_modified_masternodes: BTreeMap<UInt256, MasternodeEntry> = added_or_modified_masternodes
//             .iter()
//             .fold(BTreeMap::new(), |mut acc, _| {
//                 if let Ok(entry) = message.read_with::<MasternodeEntry>(offset, masternode_read_ctx) {
//                     acc.insert(entry.provider_registration_transaction_hash.reversed(), entry);
//                 }
//                 acc
//             });
//     }
// }

impl MNListDiff {
    pub fn new(
        message: &[u8],
        offset: &mut usize,
        provider: &dyn CoreProvider,
        protocol_version: u32,
) -> Result<Self, byte::Error> {
        let mut version = 1;
        if protocol_version >= CORE_PROTO_DIFF_VERSION_ORDER {
            version = u16::from_bytes(message, offset)?
        }
        let base_block_hash = UInt256::from_bytes(message, offset)?.0;
        let block_hash = UInt256::from_bytes(message, offset)?.0;
        let base_block_height = provider.lookup_block_height_by_hash(base_block_hash);
        let block_height = provider.lookup_block_height_by_hash(block_hash);
        let total_transactions = u32::from_bytes(message, offset)?;

        let num_merkle_hashes = VarInt::from_bytes(message, offset)?.0 as usize;
        // let arr_len = var_int.0 as usize;
        let mut merkle_hashes = Vec::with_capacity(num_merkle_hashes);
        for _i  in 0..num_merkle_hashes {
            match message.read_with::<UInt256>(offset, LE) {
                Ok(data) => { merkle_hashes.push(data.0); },
                Err(err) => { return Err(err); }
            }
        }


        // let merkle_hashes = VarArray::<[u8; 32]>::from_bytes(message, offset)?;
        let merkle_flags_count = VarInt::from_bytes(message, offset)?.0 as usize;
        let merkle_flags: &[u8] = message.read_with(offset, byte::ctx::Bytes::Len(merkle_flags_count))?;
        let coinbase_transaction = CoinbaseTransaction::from_bytes(message, offset)?;
        if protocol_version >= CORE_PROTO_BLS_BASIC && protocol_version < CORE_PROTO_DIFF_VERSION_ORDER {
            // BLS Basic
            version = u16::from_bytes(message, offset)?
        }
        let masternode_read_ctx = MasternodeReadContext(block_height, version, protocol_version);
        let deleted_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let mut deleted_masternode_hashes: Vec<[u8; 32]> =
            Vec::with_capacity(deleted_masternode_count as usize);
        for _i in 0..deleted_masternode_count {
            deleted_masternode_hashes.push(UInt256::from_bytes(message, offset)?.0);
        }
        let added_masternode_count = VarInt::from_bytes(message, offset)?.0;
        let added_or_modified_masternodes: BTreeMap<[u8; 32], MasternodeEntry> = (0..added_masternode_count)
            .fold(BTreeMap::new(), |mut acc, _| {
                if let Ok(entry) = message.read_with::<MasternodeEntry>(offset, masternode_read_ctx) {
                    acc.insert(entry.provider_registration_transaction_hash.reversed(), entry);
                }
                acc
            });

        let mut deleted_quorums: BTreeMap<LLMQType, Vec<[u8; 32]>> = BTreeMap::new();
        let mut added_quorums = Vec::<LLMQEntry>::new();
        let quorums_active = coinbase_transaction.coinbase_transaction_version >= 2;
        if quorums_active {
            let deleted_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..deleted_quorums_count {
                let llmq_type = LLMQType::from_bytes(message, offset)?;
                let llmq_hash = UInt256::from_bytes(message, offset)?.0;
                deleted_quorums
                    .entry(llmq_type)
                    .or_insert_with(Vec::new)
                    .push(llmq_hash);
            }
            let added_quorums_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..added_quorums_count {
                added_quorums.push(LLMQEntry::from_bytes(message, offset)?);
            }
        }
        let mut quorums_cls_sigs = BTreeMap::new();
        if protocol_version >= CORE_PROTO_20 {
            let quorums_cl_sigs_count = VarInt::from_bytes(message, offset)?.0;
            for _i in 0..quorums_cl_sigs_count {
                let signature = UInt768::from_bytes(message, offset)?.0;
                let index_set_length = VarInt::from_bytes(message, offset)?.0 as usize;
                let mut index_set = HashSet::with_capacity(index_set_length);
                for _i in 0..index_set_length {
                    index_set.insert(u16::from_bytes(message, offset)?);
                }
                quorums_cls_sigs.insert(signature, index_set);
            }
        }

        Ok(Self {
            base_block_hash,
            block_hash,
            total_transactions,
            merkle_hashes,
            merkle_flags: merkle_flags.to_vec(),
            coinbase_transaction,
            deleted_masternode_hashes,
            added_or_modified_masternodes,
            deleted_quorums,
            added_quorums,
            base_block_height,
            block_height,
            version,
            quorums_cls_sigs
        })
    }

    pub fn has_basic_scheme_keys(&self) -> bool {
        self.added_or_modified_masternodes.values().any(|m| m.operator_public_key.version == 2)
    }

    pub fn should_skip_removed_masternodes(&self) -> bool {
        self.version >= 2
    }
}
