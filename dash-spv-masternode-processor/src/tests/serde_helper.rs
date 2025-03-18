use dashcore::hashes::hex::FromHex;
use serde::{Deserialize, Serialize};
use dash_spv_crypto::crypto::byte_util::Reversed;
use crate::block_store::MerkleBlock;

#[derive(Serialize, Deserialize)]
#[cfg(feature = "serde")]
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
#[cfg(feature = "serde")]
pub struct PoolInfo {}

#[derive(Serialize, Deserialize)]
#[cfg(feature = "serde")]
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
#[cfg(feature = "serde")]
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

#[cfg(feature = "serde")]
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
#[cfg(feature = "serde")]
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

#[derive(Serialize, Deserialize)]
#[cfg(feature = "serde")]
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
#[cfg(feature = "serde")]
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
#[cfg(feature = "serde")]
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

pub fn bools_to_bytes(bools: Vec<bool>) -> Vec<u8> {
    let mut b = Vec::<u8>::with_capacity(bools.len() / 8);
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

#[cfg(feature = "serde")]
impl From<Block> for MerkleBlock {
    fn from(block: Block) -> Self {
        MerkleBlock {
            hash: <[u8; 32]>::from_hex(block.hash.as_str()).unwrap().reversed(),
            height: block.height as u32,
            merkleroot: <[u8; 32]>::from_hex(block.merkleroot.as_str()).unwrap()
        }
    }
}