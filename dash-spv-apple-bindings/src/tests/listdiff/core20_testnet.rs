use serde::{Deserialize, Serialize};
use dash_spv_masternode_processor::chain::common::ChainType;
use crate::tests::common::{assert_diff_result, assert_qrinfo_result, create_default_context, process_mnlistdiff, process_qrinfo, register_cache, register_default_processor, register_logger};

#[test]
pub fn test_core20_rc1_testnet() {
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let mut context = create_default_context(chain, false, cache);
    let processor = register_default_processor(&mut context);

    let result = process_mnlistdiff(chain.load_message("MNL_0_530000_70228.dat"), processor, &mut context, 70228, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    let result = process_mnlistdiff(chain.load_message("MNL_530000_904382__70230.dat"), processor, &mut context, 70230, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    context.is_dip_0024 = true;
    let result = process_qrinfo(chain.load_message("QRINFO_x3_y3__70230.dat"), processor, &mut context, 70230, false, true);
    assert_qrinfo_result(&mut context, unsafe { &*result });
}

#[test]
pub fn test_core20_activated_testnet() {
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let mut context = create_default_context(chain, false, cache);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(chain.load_message("MNL_0_530000_70228.dat"), processor, &mut context, 70228, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    let result = process_mnlistdiff(chain.load_message("MNL_530000_905465__70230.dat"), processor, &mut context, 70230, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    context.is_dip_0024 = true;
    let result = process_qrinfo(chain.load_message("QRINFO_LAST.dat"), processor, &mut context, 70230, false, true);
    assert_qrinfo_result(&mut context, unsafe { &*result });
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
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let mut context = create_default_context(chain, false, cache);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(chain.load_message("MNL_0_530000_70228.dat"), processor, &mut context, 70228, false, true);
    assert_diff_result(&mut context, unsafe { &*result });

    let files = vec![
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
    ];
    files.iter().for_each(|file_name| {
        let bytes = chain.load_message(file_name);
        let result = process_mnlistdiff(bytes, processor, &mut context, 70230, false, true);
        assert_diff_result(&mut context, unsafe { &*result });
    });
    context.is_dip_0024 = true;
    let bytes = chain.load_message("QRINFO_x3_y3__70230.dat");
    let result = process_qrinfo(bytes, processor, &mut context, 70230, false, true);
    assert_qrinfo_result(&mut context, unsafe { &*result });
}

#[test]
pub fn test_core20_activated_testnet2() {
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let mut context = create_default_context(chain, false, cache);
    let processor = register_default_processor(&mut context);
    let result = process_mnlistdiff(chain.load_message("MNL_0_530000_70228.dat"), processor, &mut context, 70228, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    let result = process_mnlistdiff(chain.load_message("MNL_530000_905465__70230.dat"), processor, &mut context, 70230, false, true);
    assert_diff_result(&mut context, unsafe { &*result });
    context.is_dip_0024 = true;
    let result = process_qrinfo(chain.load_message("QRINFO_LAST_X.dat"), processor, &mut context, 70230, false, true);
    assert_qrinfo_result(&mut context, unsafe { &*result });
}

#[test]
pub fn core20_quorum_signatures() {
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let mut context = create_default_context(chain, false, cache);
    let processor = register_default_processor(&mut context);
    let version = 70230;
    let result = process_mnlistdiff(chain.load_message("MNL_0_530000_70228.dat"), processor, &mut context, 70228, false, true);
    assert_diff_result(&mut context, unsafe { &*result });

    let diffs = [
        "530000_907104",
        "907104_907128",
        "907128_907152",
        "907152_907176",
        "907176_907200",
        "907200_907224",
        "907224_907248",
        // "907248_907272",
        // "907272_907296",
    ];
    diffs.iter().for_each(|diff| {
        let name = format!("MNL_{diff}__{version}.dat");
        let result = process_mnlistdiff(chain.load_message(name.as_str()), processor, &mut context, version, false, true);
        assert_diff_result(&mut context, unsafe { &*result });
    });

    // context.is_dip_0024 = true;
    // let result = process_qrinfo(message_from_file("testnet/QRINFO_0_907770__70230.dat"), processor, &mut context, 70230, false, true);
    // assert_qrinfo_result(&mut context, result);

}