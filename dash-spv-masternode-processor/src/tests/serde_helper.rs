use std::collections::BTreeMap;
use byte::BytesExt;
use byte::ctx::Bytes;
use hashes::hex::FromHex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use dash_spv_crypto::consensus::encode::VarInt;
use dash_spv_crypto::crypto::{UInt160, UInt256, UInt384, UInt768, VarArray};
use dash_spv_crypto::crypto::byte_util::{BytesDecodable, Reversable, Reversed};
use dash_spv_crypto::keys::OperatorPublicKey;
use dash_spv_crypto::llmq::{Bitset, LLMQEntry, LLMQVersion};
use dash_spv_crypto::network::LLMQType;
use dash_spv_crypto::tx::CoinbaseTransaction;
use dash_spv_crypto::util::base58;
use crate::block_store::MerkleBlock;
use crate::common::{LLMQSnapshotSkipMode, MasternodeType, SocketAddress};
use crate::models;
use crate::test_helpers::{block_hash_to_block_hash, message_from_file};

#[derive(Serialize, Deserialize)]
pub struct Block {
    pub hash: String,
    pub size: i64,
    pub height: i64,
    pub version: i64,
    pub merkleroot: String,
    pub tx: Vec<String>,
    pub time: i64,
    pub nonce: i64,
    pub bits: String,
    pub difficulty: f64,
    pub chainwork: String,
    pub confirmations: i64,
    pub previousblockhash: String,
    pub nextblockhash: String,
    pub reward: String,
    #[serde(rename = "isMainChain")]
    pub is_main_chain: bool,
    #[serde(rename = "poolInfo")]
    pub pool_info: PoolInfo,
}
#[derive(Serialize, Deserialize)]
pub struct PoolInfo {}

#[derive(Serialize, Deserialize)]
struct Masternode {
    #[serde(rename = "proTxHash")]
    pub pro_tx_hash: String,
    pub address: String,
    pub payee: String,
    pub status: String,
    pub pospenaltyscore: i64,
    pub lastpaidtime: i64,
    pub lastpaidblock: i64,
    pub owneraddress: String,
    pub votingaddress: String,
    pub collateraladdress: String,
    pub pubkeyoperator: String,
}

#[derive(Serialize, Deserialize)]
pub struct QRInfo {
    #[serde(rename = "extraShare")]
    pub extra_share: bool,
    #[serde(rename = "quorumSnapshotAtHMinusC")]
    pub quorum_snapshot_at_hminus_c: Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus2C")]
    pub quorum_snapshot_at_hminus2c: Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus3C")]
    pub quorum_snapshot_at_hminus3c: Snapshot,
    #[serde(rename = "mnListDiffTip")]
    pub mn_list_diff_tip: ListDiff,
    #[serde(rename = "mnListDiffH")]
    pub mn_list_diff_h: ListDiff,
    #[serde(rename = "mnListDiffAtHMinusC")]
    pub mn_list_diff_at_hminus_c: ListDiff,
    #[serde(rename = "mnListDiffAtHMinus2C")]
    pub mn_list_diff_at_hminus2c: ListDiff,
    #[serde(rename = "mnListDiffAtHMinus3C")]
    pub mn_list_diff_at_hminus3c: ListDiff,
    #[serde(rename = "lastCommitmentPerIndex")]
    pub last_commitment_per_index: Vec<Llmq>,
    #[serde(rename = "quorumSnapshotList")]
    pub quorum_snapshot_list: Vec<Snapshot>,
    #[serde(rename = "mnListDiffList")]
    pub mn_list_diff_list: Vec<ListDiff>,
}

#[derive(Serialize, Deserialize)]
pub struct Snapshot {
    #[serde(rename = "activeQuorumMembers")]
    pub active_quorum_members: Vec<bool>,
    #[serde(rename = "mnSkipListMode")]
    pub mn_skip_list_mode: i64,
    #[serde(rename = "mnSkipList")]
    pub mn_skip_list: Vec<i32>,
}

#[derive(Serialize, Deserialize)]
pub struct Llmq {
    pub version: i64,
    #[serde(rename = "llmqType")]
    pub llmq_type: i64,
    #[serde(rename = "quorumHash")]
    pub quorum_hash: String,
    #[serde(rename = "quorumIndex")]
    pub quorum_index: i64,
    #[serde(rename = "signersCount")]
    pub signers_count: usize,
    pub signers: String,
    #[serde(rename = "validMembersCount")]
    pub valid_members_count: usize,
    #[serde(rename = "validMembers")]
    pub valid_members: String,
    #[serde(rename = "quorumPublicKey")]
    pub quorum_public_key: String,
    #[serde(rename = "quorumVvecHash")]
    pub quorum_vvec_hash: String,
    #[serde(rename = "quorumSig")]
    pub quorum_sig: String,
    #[serde(rename = "membersSig")]
    pub members_sig: String,
}

impl From<Llmq> for LLMQEntry {
    fn from(llmq: Llmq) -> Self {
        LLMQEntry::new(
            LLMQVersion::from(llmq.version as u16),
            LLMQType::from(llmq.llmq_type as u8),
            block_hash_to_block_hash(llmq.quorum_hash),
            Some(llmq.quorum_index as u16),
            Bitset { count: llmq.signers_count, bitset: llmq.signers.as_bytes().to_vec() },
            Bitset { count: llmq.valid_members_count, bitset: llmq.valid_members.as_bytes().to_vec() },
            UInt384::from_hex(llmq.quorum_public_key.as_str()).unwrap().0,
            UInt256::from_hex(llmq.quorum_vvec_hash.as_str()).unwrap().0,
            UInt768::from_hex(llmq.quorum_sig.as_str()).unwrap().0,
            UInt768::from_hex(llmq.members_sig.as_str()).unwrap().0
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "proRegTxHash")]
    pub pro_reg_tx_hash: String,
    #[serde(rename = "confirmedHash")]
    pub confirmed_hash: String,
    pub service: String,
    #[serde(rename = "pubKeyOperator")]
    pub pub_key_operator: String,
    #[serde(rename = "votingAddress")]
    pub voting_address: String,
    #[serde(rename = "isValid")]
    pub is_valid: bool,

    #[serde(rename = "updateHeight")]
    pub update_height: Option<u32>,
    #[serde(rename = "knownConfirmedAtHeight")]
    pub known_confirmed_at_height: Option<u32>,

    #[serde(rename = "version")]
    pub version: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct ListDiff {
    #[serde(rename = "baseBlockHash")]
    pub base_block_hash: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "cbTxMerkleTree")]
    pub cb_tx_merkle_tree: String,
    #[serde(rename = "cbTx")]
    pub cb_tx: String,
    #[serde(rename = "deletedMNs")]
    pub deleted_mns: Vec<String>,
    #[serde(rename = "mnList")]
    pub mn_list: Vec<Node>,
    #[serde(rename = "deletedQuorums")]
    pub deleted_quorums: Vec<String>,
    #[serde(rename = "newQuorums")]
    pub new_quorums: Vec<Llmq>,
    #[serde(rename = "merkleRootMNList")]
    pub merkle_root_mnlist: String,
    #[serde(rename = "merkleRootQuorums")]
    pub merkle_root_quorums: String,
    #[serde(rename = "version")]
    pub version: Option<u16>,
}

#[derive(Serialize, Deserialize)]
pub struct MNList {
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "knownHeight")]
    pub known_height: u32,
    #[serde(rename = "masternodeMerkleRoot")]
    pub masternode_merkle_root: String,
    #[serde(rename = "quorumMerkleRoot")]
    pub quorum_merkle_root: String,
    #[serde(rename = "mnList")]
    pub mn_list: Vec<Node>,
    #[serde(rename = "newQuorums")]
    pub new_quorums: Vec<Llmq>,
}

impl From<MNList> for models::MasternodeList {
    fn from(value: MNList) -> Self {
        let block_hash = block_hash_to_block_hash(value.block_hash);
        let known_height = value.known_height;
        let masternode_merkle_root = Some(block_hash_to_block_hash(value.masternode_merkle_root));
        let llmq_merkle_root = Some(block_hash_to_block_hash(value.quorum_merkle_root));
        let masternodes = nodes_to_masternodes(value.mn_list);
        let quorums = quorums_to_quorums_map(value.new_quorums);
        models::MasternodeList {
            block_hash,
            known_height,
            masternode_merkle_root,
            llmq_merkle_root,
            masternodes,
            quorums
        }
    }
}

pub fn bools_to_bytes(bools: Vec<bool>) -> Vec<u8> {
    let mut b = Vec::<u8>::with_capacity(bools.len() / 8);
    // let mut b = [0u8; bools.len() / 8];

    for (idx, bit) in bools.into_iter().enumerate() {
        let byte = idx / 8;
        let shift = 7 - idx % 8;
        if b.get(byte).is_none() {
            b.push((bit as u8) << shift);
        } else {
            b[byte] |= (bit as u8) << shift;
        }
    }
    b
}

impl From<Snapshot> for models::LLMQSnapshot {
    fn from(snapshot: Snapshot) -> Self {
        let member_list = bools_to_bytes(snapshot.active_quorum_members);
        let skip_list = snapshot.mn_skip_list;
        let skip_list_mode = LLMQSnapshotSkipMode::from(snapshot.mn_skip_list_mode as u32);
        models::LLMQSnapshot::new(member_list, skip_list, skip_list_mode)
    }
}
impl From<&serde_json::Value> for models::LLMQSnapshot {
    fn from(value: &Value) -> Self {
        let snapshot: Snapshot = serde_json::from_value(value.clone()).unwrap();
        let member_list = bools_to_bytes(snapshot.active_quorum_members);
        let skip_list = snapshot.mn_skip_list;
        let skip_list_mode = LLMQSnapshotSkipMode::from(snapshot.mn_skip_list_mode as u32);
        models::LLMQSnapshot::new(member_list, skip_list, skip_list_mode)
    }
}
impl From<&serde_json::Value> for models::MasternodeList {
    fn from(value: &Value) -> Self {
        let nodes: Vec<Node> = serde_json::from_value(value.clone()).unwrap();
        let masternodes = nodes_to_masternodes(nodes);
        models::MasternodeList {
            block_hash: Default::default(),
            known_height: 0,
            masternode_merkle_root: None,
            llmq_merkle_root: None,
            masternodes,
            quorums: Default::default()
        }
    }
}

pub fn quorums_to_quorums_vec(value: Vec<Llmq>) -> Vec<LLMQEntry> {
    value.into_iter().map(LLMQEntry::from).collect()
}

pub fn quorums_to_quorums_map(value: Vec<Llmq>) -> BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>> {
    let mut quorums: BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>> = BTreeMap::new();
    value.into_iter().for_each(|llmq| {
        let entry = LLMQEntry::from(llmq);
        quorums
            .entry(entry.llmq_type)
            .or_insert_with(BTreeMap::new)
            .insert(entry.llmq_hash, entry);

    });
    quorums
}

pub fn nodes_to_masternodes(value: Vec<Node>) -> BTreeMap<[u8; 32], models::MasternodeEntry> {
    let map: BTreeMap<[u8; 32], models::MasternodeEntry> = value
        .into_iter()
        .map(|node| {
            let provider_registration_transaction_hash = UInt256::from_hex(node.pro_reg_tx_hash.as_str()).unwrap().0;
            let confirmed_hash = UInt256::from_hex(node.confirmed_hash.as_str()).unwrap().0;
            // node.service don't really need
            let socket_address = SocketAddress { ip_address: Default::default(), port: 0 };
            let voting_bytes = base58::from(node.voting_address.as_str()).unwrap();
            let key_id_voting = UInt160::from_bytes(&voting_bytes, &mut 0).unwrap().0;
            let public_key = UInt384::from_hex(node.pub_key_operator.as_str()).unwrap().0;
            let version = node.version.unwrap_or(0);
            let is_valid = u8::from(node.is_valid);
            let operator_public_key = OperatorPublicKey {
                data: public_key,
                version
            };
            let update_height = node.update_height.unwrap_or(0);
            let mut masternode = models::MasternodeEntry::new(version, provider_registration_transaction_hash, confirmed_hash, socket_address, key_id_voting, operator_public_key, is_valid, MasternodeType::Regular, 0, [0u8; 20], update_height, 70219);
            masternode.known_confirmed_at_height = node.known_confirmed_at_height;
            masternode
        })
        .fold(BTreeMap::new(), |mut acc, entry| {
            let hash = entry.provider_registration_transaction_hash.reversed();
            acc.insert(hash, entry);
            acc
        });
    map
}

pub fn masternode_list_from_genesis_diff<BHL: Fn(UInt256) -> u32 + Copy>(
    diff: ListDiff, block_height_lookup: BHL, is_bls_basic: bool) -> models::MNListDiff {
    let base_block_hash = UInt256::from_hex(diff.base_block_hash.as_str()).unwrap().reverse().0;
    let block_hash = UInt256::from_hex(diff.block_hash.as_str()).unwrap().reverse().0;
    let cb_tx_bytes = Vec::from_hex(diff.cb_tx.as_str()).unwrap();
    let coinbase_transaction = CoinbaseTransaction::from_bytes(&cb_tx_bytes, &mut 0).unwrap();
    // let tree_bytes = diff.cb_tx_merkle_tree.as_bytes();
    let tree_bytes = Vec::from_hex(diff.cb_tx_merkle_tree.as_str()).unwrap();
    let tree_bytes = tree_bytes.as_slice();

    let offset = &mut 0;
    let total_transactions = u32::from_bytes(tree_bytes, offset).unwrap();
    let merkle_hashes = VarArray::<UInt256>::from_bytes(tree_bytes, offset).unwrap();
    let merkle_flags_var_int: VarInt = VarInt::from_bytes(tree_bytes, offset).unwrap();
    let merkle_flags_count = merkle_flags_var_int.0 as usize;
    let merkle_flags: &[u8] = tree_bytes.read_with(offset, Bytes::Len(merkle_flags_count)).unwrap();
    let version = diff.version.unwrap_or(0);

    let deleted_masternode_hashes = diff.deleted_mns.iter().map(|s| UInt256::from_hex(s.as_str()).unwrap().0).collect();
    let added_or_modified_masternodes = nodes_to_masternodes(diff.mn_list);
    // in that snapshot it's always empty
    let deleted_quorums = BTreeMap::default();
    let added_quorums = quorums_to_quorums_vec(diff.new_quorums);
    println!("block_hash_tip: {}", block_hash);
    models::MNListDiff {
        base_block_hash,
        block_hash,
        total_transactions,
        merkle_hashes: merkle_hashes.1,
        merkle_flags: merkle_flags.to_vec(),
        coinbase_transaction,
        deleted_masternode_hashes,
        added_or_modified_masternodes,
        deleted_quorums,
        added_quorums,
        base_block_height: block_height_lookup(base_block_hash),
        block_height: block_height_lookup(block_hash),
        version,
        // TODO: update json
        quorums_cls_sigs: BTreeMap::new(),
    }
}

pub fn masternode_list_from_json(filename: String) -> models::MasternodeList {
    From::<MNList>::from(serde_json::from_slice(&message_from_file(filename.as_str())).unwrap())
}

impl From<Block> for MerkleBlock {
    fn from(block: Block) -> Self {
        MerkleBlock {
            hash: UInt256::from_hex(block.hash.as_str()).unwrap().reverse(),
            height: block.height as u32,
            merkleroot: UInt256::from_hex(block.merkleroot.as_str()).unwrap()
        }
    }
}