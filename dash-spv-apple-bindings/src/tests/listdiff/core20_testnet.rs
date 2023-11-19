use serde::{Deserialize, Serialize};
use dash_spv_masternode_processor::chain::common::ChainType;
use crate::tests::common::assert_diff_chain;

#[test]
pub fn test_core20_rc1_testnet() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_530000__70228.dat", "MNL_530000_904382__70230.dat"],
        &["QRINFO_x3_y3__70230.dat"],
        None);
}

#[test]
pub fn test_core20_activated_testnet() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_530000__70228.dat", "MNL_530000_905465__70230.dat"],
        &["QRINFO_LAST__70230.dat"],
        None);
}

#[derive(Serialize, Deserialize)]
struct LLMQ {
    pub version: i64,
    #[serde(rename = "llmqType")]
    pub llmq_type: i64,
    #[serde(rename = "quorumHash")]
    pub quorum_hash: String,
    #[serde(rename = "quorumIndex")]
    pub quorum_index: i64,
    #[serde(rename = "signersCount")]
    pub signers_count: i64,
    pub signers: String,
    #[serde(rename = "validMembersCount")]
    pub valid_members_count: i64,
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
struct Masternode {
    #[serde(rename = "nVersion")]
    pub n_version: i64,
    #[serde(rename = "nType")]
    pub n_type: i64,
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
}

#[derive(Serialize, Deserialize)]
struct QRInfoV20 {
    #[serde(rename = "extraShare")]
    pub extra_share: bool,
    #[serde(rename = "quorumSnapshotAtHMinusC")]
    pub quorum_snapshot_at_hminus_c: dash_spv_masternode_processor::test_helpers::Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus2C")]
    pub quorum_snapshot_at_hminus2c: dash_spv_masternode_processor::test_helpers::Snapshot,
    #[serde(rename = "quorumSnapshotAtHMinus3C")]
    pub quorum_snapshot_at_hminus3c: dash_spv_masternode_processor::test_helpers::Snapshot,
    #[serde(rename = "mnListDiffTip")]
    pub mn_list_diff_tip: ListDiff_70230,
    #[serde(rename = "mnListDiffH")]
    pub mn_list_diff_h: ListDiff_70230,
    #[serde(rename = "mnListDiffAtHMinusC")]
    pub mn_list_diff_at_hminus_c: ListDiff_70230,
    #[serde(rename = "mnListDiffAtHMinus2C")]
    pub mn_list_diff_at_hminus2c: ListDiff_70230,
    #[serde(rename = "mnListDiffAtHMinus3C")]
    pub mn_list_diff_at_hminus3c: ListDiff_70230,
    #[serde(rename = "lastCommitmentPerIndex")]
    pub last_commitment_per_index: Vec<LLMQ>,
    #[serde(rename = "quorumSnapshotList")]
    pub quorum_snapshot_list: Vec<dash_spv_masternode_processor::test_helpers::Snapshot>,
    #[serde(rename = "mnListDiffList")]
    pub mn_list_diff_list: Vec<ListDiff_70230>,
}

#[derive(Serialize, Deserialize)]
struct DeletedLLMQ {
    #[serde(rename = "llmqType")]
    pub llmq_type: i64,
    #[serde(rename = "quorumHash")]
    pub quorum_hash: String,
}
#[derive(Serialize, Deserialize)]
struct LLMQCLSig {

}

#[allow(non_camel_case_types)]
#[derive(Serialize, Deserialize)]
struct ListDiff_70230 {
    #[serde(rename = "nVersion")]
    pub n_version: i64,
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
    pub mn_list: Vec<Masternode>,
    #[serde(rename = "deletedQuorums")]
    pub deleted_quorums: Vec<DeletedLLMQ>,
    #[serde(rename = "newQuorums")]
    pub new_quorums: Vec<LLMQ>,
    #[serde(rename = "merkleRootMNList")]
    pub merkle_root_mnlist: String,
    #[serde(rename = "merkleRootQuorums")]
    pub merkle_root_quorums: String,
    #[serde(rename = "quorumsCLSigs")]
    pub quorums_clsigs: Vec<LLMQCLSig>,
}



#[test]
pub fn test_core_20_rc1_testnet_etalon() {
    let qrinfo_8792: QRInfoV20 = serde_json::from_slice(&ChainType::TestNet.load_message("qrinfo_530000_904144__70230.json")).unwrap();
    println!("qrinfo");
}


#[test]
pub fn test_core20_rc2_testnet() {
    assert_diff_chain(
        ChainType::TestNet,
        &[
            "MNL_0_530000__70228.dat",
            "MNL_530000_905522__70230.dat",
            "MNL_530000_904944__70230.dat",
            "MNL_904944_904968__70230.dat",
            "MNL_904968_904992__70230.dat",
            "MNL_904992_905016__70230.dat",
            "MNL_905016_905040__70230.dat",
            "MNL_905040_905064__70230.dat",
            "MNL_905064_905088__70230.dat",
            "MNL_905088_905112__70230.dat",
            "MNL_905112_905136__70230.dat",
            "MNL_905136_905160__70230.dat",
            "MNL_905160_905184__70230.dat",
            "MNL_905184_905208__70230.dat",
            "MNL_905208_905232__70230.dat",
            "MNL_905232_905256__70230.dat",
            "MNL_905256_905280__70230.dat",
            "MNL_905280_905304__70230.dat",
            "MNL_905304_905328__70230.dat",
            "MNL_905328_905352__70230.dat",
            "MNL_905352_905376__70230.dat",
            "MNL_905376_905400__70230.dat",
            "MNL_905400_905424__70230.dat",
            "MNL_905424_905448__70230.dat",
            "MNL_905448_905472__70230.dat",
            "MNL_905472_905496__70230.dat",
            "MNL_905496_905522__70230.dat",
            "MNL_905522_905523__70230.dat",
            "MNL_905523_905524__70230.dat",
            "MNL_905524_905525__70230.dat",
        ],
        &["QRINFO_x3_y3__70230.dat"],
        None);
}

#[test]
pub fn test_core20_activated_testnet2() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_530000__70228.dat", "MNL_530000_905465__70230.dat"],
        &["QRINFO_LAST_X__70230.dat"],
        None);
}

#[test]
pub fn core20_quorum_signatures() {
    assert_diff_chain(
        ChainType::TestNet,
    &[
        "MNL_0_530000__70228.dat",
        "MNL_530000_907104__70230.dat",
        "MNL_907104_907128__70230.dat",
        "MNL_907128_907152__70230.dat",
        "MNL_907152_907176__70230.dat",
        "MNL_907176_907200__70230.dat",
        "MNL_907200_907224__70230.dat",
        "MNL_907224_907248__70230.dat",
        // "MNL_907248_907272__70230.dat",
        // "MNL_907272_907296__70230.dat",
    ],
    &[/*"QRINFO_0_907770__70230.dat"*/],
        None);
}