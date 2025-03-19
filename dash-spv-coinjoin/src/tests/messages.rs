use std::io::Cursor;
use dashcore::blockdata::transaction::Transaction;
use dashcore::consensus::{Decodable, Encodable};
use dashcore::hashes::Hash;
use dashcore::hashes::hex::FromHex;
use dashcore::hash_types::ProTxHash;
use dashcore::prelude::DisplayHex;
use dashcore::bls_sig_utils::BLSSignature;
use dash_spv_crypto::crypto::byte_util::Reversed;
use crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;
use crate::messages::{CoinJoinAcceptMessage, CoinJoinCompleteMessage, CoinJoinEntry, CoinJoinFinalTransaction, CoinJoinQueueMessage, CoinJoinSignedInputs, CoinJoinStatusUpdate, PoolMessage, PoolState, PoolStatusUpdate};

#[test]
pub fn test_coinjoin_accept_message() {
    // CoinJoinAcceptMessage(denomination=16, txCollateral=956685418a5c4fecaedf74d2ac56862e22830658b6b256e4e2dea0b665e1f756)
    let payload = Vec::from_hex("100000000100000001c493c126391c84670115d1d5ed81b27a741a99a8942289bc82396da0b490795c000000006b483045022100d9899056ed6aceee4411b965a07a4a624fc43faca0112fae49129101942ae42f02205b92eefecf87975a356fd80a918978da49594baf8bb1082f527542e56f4f191d012102bc626099759860a95d13a6cdeb754efa5deec2178cc65142b92bbd90ab4d1364ffffffff01204e0000000000001976a914b2705af1d15ee81e96fce5ec49cd9ed6639362f188ac00000000").unwrap();
    let tx_id = <[u8; 32]>::from_hex("956685418a5c4fecaedf74d2ac56862e22830658b6b256e4e2dea0b665e1f756").unwrap().reversed();
   
    let mut cursor = Cursor::new(&payload);
    let dca = CoinJoinAcceptMessage::consensus_decode(&mut cursor).unwrap();
    
    let mut buffer = Vec::new();
    dca.consensus_encode(&mut buffer).unwrap();

    assert_eq!(16, dca.denomination);
    assert_eq!(buffer.to_lower_hex_string(), payload.to_lower_hex_string());
    assert_eq!(tx_id, dca.tx_collateral.txid().to_byte_array());
}


#[test]
pub fn test_coinjoin_complete_message() {
    // CoinJoinComplete(msgSessionID=549379, msgMessageID=20)
    let payload = Vec::from_hex("0362080014000000").unwrap();

    let mut cursor = Cursor::new(&payload);
    let dsc = CoinJoinCompleteMessage::consensus_decode(&mut cursor).unwrap();

    let from_ctor = CoinJoinCompleteMessage {
        msg_session_id: 549379, 
        msg_message_id: PoolMessage::MsgSuccess
    };
    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(20, dsc.msg_message_id.value());
    assert_eq!(549379, dsc.msg_session_id);
    assert_eq!(buffer.to_lower_hex_string(), payload.to_lower_hex_string());
}

#[test]
pub fn test_coinjoin_final_transaction() {
    // CoinJoinFinalTransaction(msgSessionID=512727, transaction=a57015f0f8c85cdee8ab47d9bb7792c23c21bfbad1a19b7b4368915ba970fae1)
    let payload = Vec::from_hex("d7d20700020000000424e55da190e79da9540b0fc87e859261e4a2a33530a005cab68f5cd3ece0234a0200000000fffffffff7b9fdaf651dc308b6f538ac9dae090268f08f424fd91c705fe5d12174999f5d0400000000ffffffff20d63b2ca93309e3526cac6fab31545bd932ba705e7011e720ba69af59baaba10000000000ffffffff20d63b2ca93309e3526cac6fab31545bd932ba705e7011e720ba69af59baaba10300000000ffffffff044a420f00000000001976a914257b0482306f29fe7d97fb8b847746ba4a1606e588ac4a420f00000000001976a9146662e6130b7b1f06778ae1e24b687db752e1a83d88ac4a420f00000000001976a914ac2faba75d50cdd8dff86b8a457c45201aefb96f88ac4a420f00000000001976a914b89ab9894c767e22e85e2164b9f65fc0a4c3dc7e88ac00000000").unwrap();
    let tx_id = <[u8; 32]>::from_hex("a57015f0f8c85cdee8ab47d9bb7792c23c21bfbad1a19b7b4368915ba970fae1").unwrap().reversed();
   
    let mut cursor = Cursor::new(&payload);
    let dsf = CoinJoinFinalTransaction::consensus_decode(&mut cursor).unwrap();
    
    let tx_hash = dsf.tx.txid();
    let from_ctor = CoinJoinFinalTransaction {
        msg_session_id: 512727, 
        tx: dsf.tx
    };
    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(512727, dsf.msg_session_id);
    assert_eq!(tx_id, tx_hash.to_byte_array());
    assert_eq!(buffer.to_lower_hex_string(), payload.to_lower_hex_string());
}

#[test]
pub fn test_coinjoin_status_update_from_payload() {
    // CoinJoinStatusUpdate(sessionID=783283, state=POOL_STATE_QUEUE, statusUpdate=STATUS_REJECTED, messageID=ERR_DENOM)
    let mut payload = Vec::from_hex("b3f30b00010000000000000001000000").unwrap();
    let mut cursor = Cursor::new(&payload);
    let mut dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(783283, dssu.session_id);
    assert_eq!(PoolState::Queue, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::Rejected, dssu.status_update);
    assert_eq!(PoolMessage::ErrDenom, dssu.message_id);

    payload = Vec::from_hex("d7d20700030000000100000013000000").unwrap();
    cursor = Cursor::new(&payload);
    dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(512727, dssu.session_id);
    assert_eq!(PoolState::Signing, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::Accepted, dssu.status_update);
    assert_eq!(PoolMessage::MsgNoErr, dssu.message_id);
}

#[test]
pub fn test_coinjoin_status_update_from_ctor() {
    let payload = Vec::from_hex("5faa0c00010000000100000013000000").unwrap();
    let mut cursor = Cursor::new(&payload);
    let dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(830047, dssu.session_id);
    assert_eq!(PoolState::Queue, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::Accepted, dssu.status_update);
    assert_eq!(PoolMessage::MsgNoErr, dssu.message_id);
   
    let from_ctor = CoinJoinStatusUpdate {
        session_id: 830047,
        pool_state: PoolState::Queue,
        status_update: PoolStatusUpdate::Accepted,
        message_id: PoolMessage::MsgNoErr
    };

    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(buffer.to_lower_hex_string(), payload.to_lower_hex_string());
}

#[test]
pub fn coinjoin_signed_inputs_round_test() {
    let tx_data = Vec::from_hex("02000000042607763cf6eceb2478060ead38fbb3151b7676b6a243e78b58c420a4ad99cb05010000006a47304402201f95f3a194bd51c521adcd46173d3d5c9bd2dd148004dd1da72e686fd6d946e4022020e34d85cd817aff0663b133915ca2eda5ecd5d5a93fba33f2e9644f1d1513a3012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffffe27ecbb210e98a5d2dba6e3bfa0732b8f6371155c3f8bd0420027d2eb3d24a7d010000006b483045022100c7d5c710ebdf8a2526389347823c3de83b3da498eeac5d1e9001e2e86f4cd0d002200e91ee98abc4f5fb5a78e8e80ed6fd17697a706e7118f87e545d8fdad65a845b012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff70a65da4b8d4438058c2e8f36811577cdb244d33c7973644386259135e3635a3010000006b483045022100d1c279574bdb0a4c72b6a11247f2945746b50f3a847c9c6925f0badfa8f5827a0220059884f1e9099fcfbb4966cced355e764ddf18bc60a3e03a3804c0c9b20618a4012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff4605e08cc9758029e89705c41872f063854684b5abf2020e56aca53f161b3fea000000006b483045022100f5afc8c1e722b25532b0a3561f0c37cf80bcd288a40fa0ced53d9a137f06dbc8022067c8ad28484b4a504f74cc7ad754ab4b87f0fbb46a4725e915b625eb000be8fd012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff02224e0000000000001976a914b889fb3449a36530c85d9689c4773c5cd1ba223388ac51844c8c060000001976a9140d5bcbeeb459af40f97fcb4a98e9d1ed13e904c888acb1f80a00").unwrap();
    let mut cursor = Cursor::new(&tx_data);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();

    let dss = CoinJoinSignedInputs { inputs: tx.input }; // using inputs from the transaction above
    let mut buffer = Vec::new();
    dss.consensus_encode(&mut buffer).unwrap();

    cursor = Cursor::new(&buffer);
    let from_bytes = CoinJoinSignedInputs::consensus_decode(&mut cursor).unwrap();

    assert_eq!(4, from_bytes.inputs.len());
    assert_eq!(4, dss.inputs.len());
    assert_eq!(from_bytes.inputs[0].previous_output.txid, dss.inputs[0].previous_output.txid);
    assert_eq!(from_bytes.inputs[2].previous_output.txid, dss.inputs[2].previous_output.txid);
}

#[test]
pub fn coinjoin_entry_round_test() {
    let mut tx_data = Vec::from_hex("02000000042607763cf6eceb2478060ead38fbb3151b7676b6a243e78b58c420a4ad99cb05010000006a47304402201f95f3a194bd51c521adcd46173d3d5c9bd2dd148004dd1da72e686fd6d946e4022020e34d85cd817aff0663b133915ca2eda5ecd5d5a93fba33f2e9644f1d1513a3012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffffe27ecbb210e98a5d2dba6e3bfa0732b8f6371155c3f8bd0420027d2eb3d24a7d010000006b483045022100c7d5c710ebdf8a2526389347823c3de83b3da498eeac5d1e9001e2e86f4cd0d002200e91ee98abc4f5fb5a78e8e80ed6fd17697a706e7118f87e545d8fdad65a845b012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff70a65da4b8d4438058c2e8f36811577cdb244d33c7973644386259135e3635a3010000006b483045022100d1c279574bdb0a4c72b6a11247f2945746b50f3a847c9c6925f0badfa8f5827a0220059884f1e9099fcfbb4966cced355e764ddf18bc60a3e03a3804c0c9b20618a4012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff4605e08cc9758029e89705c41872f063854684b5abf2020e56aca53f161b3fea000000006b483045022100f5afc8c1e722b25532b0a3561f0c37cf80bcd288a40fa0ced53d9a137f06dbc8022067c8ad28484b4a504f74cc7ad754ab4b87f0fbb46a4725e915b625eb000be8fd012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff02224e0000000000001976a914b889fb3449a36530c85d9689c4773c5cd1ba223388ac51844c8c060000001976a9140d5bcbeeb459af40f97fcb4a98e9d1ed13e904c888acb1f80a00").unwrap();
    let mut cursor = Cursor::new(&tx_data);
    let tx1 = Transaction::consensus_decode(&mut cursor).unwrap();

    tx_data = Vec::from_hex("01000000033f90cbc2d751c77358b3ff37efd72936b389a17b9ec72bdec4678394814cfe2d000000006a473044022050d2f3b6f097f1973b29bb5a0e98f307f6fc338bb8d29e4a7eb257eebd147ccd022055f88aa06cf90aec97991db9c351fd622fa60fe2cb6bbe6df2ecfef03ca047fa012102d336120a91d7d3497056715f6078e36c56e84c41038cf630260ef3245f6ba39effffffff94cae0fa480e004218a66ea7eae8c0a1a39dbd8ebba966004ddfdcac1e11f089000000006b483045022100ed1fbe54b90c8d69e616b79ba5e03e192bdee6b26f66d40d9da14ae7c7e64a9c022062c54fb1635937a38f3b43b504777c9faf357734cad6f53130870f7e980a3be60121037c4c4205eceb06bbf1e4894e52ecddcf700e1a699e2a4cbee9fd7ed748fb7a59ffffffff3e2611f35c7a2fefadce6b115ce8e14b31b627667af9c04909c0ddcceb8294a3000000006a473044022036bed2e8600ed1a715618ca398553254c14fcea824b77ed784cee5f5b23b84df022041c4821e6e639169ddc891e4d6b4e146e5f4684e5687daf5fcce2fd1f73392230121037c4c4205eceb06bbf1e4894e52ecddcf700e1a699e2a4cbee9fd7ed748fb7a59ffffffff0260182300000000001976a9140205411ec940f9139ea72e3a999d21fceff671e688ac4dc27200000000001976a91425b2b9126bf32e6115a813d019e72b7b9106211b88ac00000000").unwrap();
    cursor = Cursor::new(&tx_data);
    let tx2 = Transaction::consensus_decode(&mut cursor).unwrap();

    let dsi = CoinJoinEntry {
        mixing_inputs: tx1.input,
        mixing_outputs: tx1.output,
        tx_collateral: tx2
    };
    
    let mut buffer = Vec::new();
    dsi.consensus_encode(&mut buffer).unwrap();

    cursor = Cursor::new(&buffer);
    let from_bytes = CoinJoinEntry::consensus_decode(&mut cursor).unwrap();

    assert_eq!(4, from_bytes.mixing_inputs.len());
    assert_eq!(4, dsi.mixing_inputs.len());
    assert_eq!(2, from_bytes.mixing_outputs.len());
    assert_eq!(2, dsi.mixing_outputs.len());

    assert_eq!(from_bytes.mixing_inputs[0].previous_output.txid, dsi.mixing_inputs[0].previous_output.txid);
    assert_eq!(from_bytes.mixing_inputs[2].previous_output.txid, dsi.mixing_inputs[2].previous_output.txid);

    assert_eq!(from_bytes.mixing_outputs[0].value, dsi.mixing_outputs[0].value);
    assert_eq!(from_bytes.mixing_outputs[1].value, dsi.mixing_outputs[1].value);

    assert_eq!(from_bytes.tx_collateral.txid(), dsi.tx_collateral.txid());
}

#[test]
pub fn coinjoin_entry_test() {
    let dsi_message = Vec::from_hex("05a57b11f764c258688b0dd9557147aafac15165729b65a09180436f56a4c0709d0100000000ffffffff6eb1d7c1ba2dd0bab9c158e9aa9535614c518e700c7155ac95f5f8db70dd235a0000000000ffffffff2126f88ff1a1d77012083cf291ce395d37079ecff1c3ab30c3869d5493b387800000000000ffffffffc692fbe122b3934d1926b1f19b14137b24a9a7182937d35e99ad7da24aae4dab0200000000ffffffffac65973a3c7c45ad2ddb033ca2c224b7a151f847716d5449ba912b3868ff71c40000000000ffffffff0100000001dd86755f2cb8d67c52da2fc42c9a97a2b08e6de01f94037390d46fae68e8ed99000000006b483045022100954aa1d666906e78bcc42806874f153d31d5e1e4ae18dcadcbf8dbfc1123e3900220732c82db96098bbee7a69f284464d5233de0e2adf23401552bf2eba1623509fb0121036bfa0b828ff9b020750e765158495979bea2134b13386e6655e00ce1b9cbe980ffffffff0110270000000000001976a9146f6293e33e78ae0f2d74ba1922b86794b9efb08288ac0000000005a1860100000000001976a914b0a180dfd44ba7066f5f42f3eaf431f0cd668fe388aca1860100000000001976a914799bcbf0ff47c4e83fbf1db27a337cc89ed8407088aca1860100000000001976a914060ae9e82d52804b66911e8aa4e94d88665ec19f88aca1860100000000001976a914a48fd783b7a6aad534a91f941a9665c8ecf0964388aca1860100000000001976a91466dd8d620782a0d89e63f0ff2d7935c46e053a4288ac").unwrap();
    let mut cursor = Cursor::new(&dsi_message);
    let entry = CoinJoinEntry::consensus_decode(&mut cursor).unwrap();

    let tx_collateral_bytes = Vec::from_hex("0100000001dd86755f2cb8d67c52da2fc42c9a97a2b08e6de01f94037390d46fae68e8ed99000000006b483045022100954aa1d666906e78bcc42806874f153d31d5e1e4ae18dcadcbf8dbfc1123e3900220732c82db96098bbee7a69f284464d5233de0e2adf23401552bf2eba1623509fb0121036bfa0b828ff9b020750e765158495979bea2134b13386e6655e00ce1b9cbe980ffffffff0110270000000000001976a9146f6293e33e78ae0f2d74ba1922b86794b9efb08288ac00000000").unwrap();
    cursor = Cursor::new(&tx_collateral_bytes);
    let collateral_tx = Transaction::consensus_decode(&mut cursor).unwrap();
    assert_eq!(collateral_tx, entry.tx_collateral);
    assert_eq!(5, entry.mixing_inputs.len());
    assert_eq!(5, entry.mixing_outputs.len());
}

#[test]
pub fn coinjoin_broadcast_tx_round_test() {
    let tx_data = Vec::from_hex("02000000042607763cf6eceb2478060ead38fbb3151b7676b6a243e78b58c420a4ad99cb05010000006a47304402201f95f3a194bd51c521adcd46173d3d5c9bd2dd148004dd1da72e686fd6d946e4022020e34d85cd817aff0663b133915ca2eda5ecd5d5a93fba33f2e9644f1d1513a3012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffffe27ecbb210e98a5d2dba6e3bfa0732b8f6371155c3f8bd0420027d2eb3d24a7d010000006b483045022100c7d5c710ebdf8a2526389347823c3de83b3da498eeac5d1e9001e2e86f4cd0d002200e91ee98abc4f5fb5a78e8e80ed6fd17697a706e7118f87e545d8fdad65a845b012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff70a65da4b8d4438058c2e8f36811577cdb244d33c7973644386259135e3635a3010000006b483045022100d1c279574bdb0a4c72b6a11247f2945746b50f3a847c9c6925f0badfa8f5827a0220059884f1e9099fcfbb4966cced355e764ddf18bc60a3e03a3804c0c9b20618a4012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff4605e08cc9758029e89705c41872f063854684b5abf2020e56aca53f161b3fea000000006b483045022100f5afc8c1e722b25532b0a3561f0c37cf80bcd288a40fa0ced53d9a137f06dbc8022067c8ad28484b4a504f74cc7ad754ab4b87f0fbb46a4725e915b625eb000be8fd012102bf7c36100b0d394e79a1704b8bf9e030a62e139a293f5da891671c56d555f732feffffff02224e0000000000001976a914b889fb3449a36530c85d9689c4773c5cd1ba223388ac51844c8c060000001976a9140d5bcbeeb459af40f97fcb4a98e9d1ed13e904c888acb1f80a00").unwrap();
    let mut cursor = Cursor::new(&tx_data);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();
    let pro_tx_hash = <[u8; 32]>::from_hex("3fc39b657385a7d2e824ca2644bdcddcef0bc25775c30c4f747345ef4f1c7503").unwrap().reversed();
    let signature = Vec::from_hex("998c5118eef9a89bfe5c6b961a8cc5af52cb00d0394688e78b23194699f7356cece6f8af63fdb0c28c2728c05325a6fe").unwrap();
    let signature_time: i64 = 1702813411;

    let dstx = CoinJoinBroadcastTx::new(tx, pro_tx_hash, Some(signature), signature_time);
    let mut buffer = Vec::new();
    dstx.consensus_encode(&mut buffer).unwrap();

    cursor = Cursor::new(&buffer);
    let from_bytes = CoinJoinBroadcastTx::consensus_decode(&mut cursor).unwrap();

    assert_eq!(dstx.tx.txid(), from_bytes.tx.txid());
    assert_eq!(dstx.pro_tx_hash, from_bytes.pro_tx_hash);
    assert_eq!(dstx.signature.unwrap().to_lower_hex_string(), from_bytes.signature.unwrap().to_lower_hex_string());
    assert_eq!(dstx.signature_time, from_bytes.signature_time);
}

#[test]
pub fn coinjoin_queue_message_test() {    
    let payload = Vec::from_hex("0800000036c6298f595939395ec930f936452726f33a311a79b2abe290ae01aad020011652498465000000000060a4f1ebf98b3b2df98c6375d391c4aba667edbaccb31610a8ded1eaba92c87ce59d2dcbea67fd59d212edd87553fbbeac0041bc514782b3ae5184f6d194c3dbdd8f94b5ce5e0e358aed3557b18188d51cbbcda80fba2ff7dabb808029ba255431").unwrap();
    let mut cursor = Cursor::new(&payload);
    let queue_from_hex = CoinJoinQueueMessage::consensus_decode(&mut cursor).unwrap();

    assert_eq!(8, queue_from_hex.denomination);
    assert_eq!(ProTxHash::from_byte_array(<[u8; 32]>::from_hex("160120d0aa01ae90e2abb2791a313af326274536f930c95e393959598f29c636").unwrap().reversed()), queue_from_hex.pro_tx_hash);
    assert_eq!(1703168338, queue_from_hex.time);
    assert_eq!(false, queue_from_hex.ready);
    assert_eq!(BLSSignature::from_hex("a4f1ebf98b3b2df98c6375d391c4aba667edbaccb31610a8ded1eaba92c87ce59d2dcbea67fd59d212edd87553fbbeac0041bc514782b3ae5184f6d194c3dbdd8f94b5ce5e0e358aed3557b18188d51cbbcda80fba2ff7dabb808029ba255431").unwrap(), queue_from_hex.signature.unwrap());

    let queue_from_ctor = CoinJoinQueueMessage {
        denomination: 8,
        pro_tx_hash: ProTxHash::from_byte_array(<[u8; 32]>::from_hex("160120d0aa01ae90e2abb2791a313af326274536f930c95e393959598f29c636").unwrap().reversed()),
        time: 1703168338,
        ready: false,
        signature: BLSSignature::from_hex("a4f1ebf98b3b2df98c6375d391c4aba667edbaccb31610a8ded1eaba92c87ce59d2dcbea67fd59d212edd87553fbbeac0041bc514782b3ae5184f6d194c3dbdd8f94b5ce5e0e358aed3557b18188d51cbbcda80fba2ff7dabb808029ba255431").ok(),
        tried: false
    };

    let mut buffer = Vec::new();
    queue_from_ctor.consensus_encode(&mut buffer).unwrap();
    assert_eq!(queue_from_hex, queue_from_ctor);
    assert_eq!(buffer.to_lower_hex_string(), payload.to_lower_hex_string());
    assert_eq!(false, queue_from_ctor.tried);

    let operator_key = <[u8; 48]>::from_hex("066d57a6451b7800c1c2a6c6e04fe73ec2e1c95e492bacae760ad2f79ca3c30727ec9bf0daea43c08ff1ad6c2cf07612").unwrap();
    println!("op_key raw data: {}", operator_key.to_lower_hex_string());

    assert!(queue_from_ctor.check_signature(operator_key, true));
}
