use dash_spv_masternode_processor::consensus::{Decodable, Encodable};
use dash_spv_masternode_processor::hashes::hex::{FromHex, ToHex};
use dash_spv_masternode_processor::crypto::byte_util::Reversable;
use dash_spv_masternode_processor::crypto::UInt256;
use std::io::Cursor;

use crate::messages::coinjoin_accept_message::CoinJoinAcceptMessage;
use crate::messages::coinjoin_complete_message::CoinJoinCompleteMessage;
use crate::messages::coinjoin_final_transaction::CoinJoinFinalTransaction;
use crate::messages::coinjoin_status_update::CoinJoinStatusUpdate;
use crate::messages::pool_message::PoolMessage;
use crate::messages::pool_state::PoolState;
use crate::messages::pool_status_update::PoolStatusUpdate;

#[test]
pub fn test_coinjoin_accept_message() {
    // CoinJoinAcceptMessage(denomination=16, txCollateral=956685418a5c4fecaedf74d2ac56862e22830658b6b256e4e2dea0b665e1f756)
    let payload = Vec::from_hex("100000000100000001c493c126391c84670115d1d5ed81b27a741a99a8942289bc82396da0b490795c000000006b483045022100d9899056ed6aceee4411b965a07a4a624fc43faca0112fae49129101942ae42f02205b92eefecf87975a356fd80a918978da49594baf8bb1082f527542e56f4f191d012102bc626099759860a95d13a6cdeb754efa5deec2178cc65142b92bbd90ab4d1364ffffffff01204e0000000000001976a914b2705af1d15ee81e96fce5ec49cd9ed6639362f188ac00000000").unwrap();
    let tx_id = UInt256::from_hex("956685418a5c4fecaedf74d2ac56862e22830658b6b256e4e2dea0b665e1f756").unwrap().reversed();
   
    let mut cursor = Cursor::new(&payload);
    let dca = CoinJoinAcceptMessage::consensus_decode(&mut cursor).unwrap();
    
    let mut buffer = Vec::new();
    dca.consensus_encode(&mut buffer).unwrap();

    assert_eq!(16, dca.denomination);
    assert_eq!(buffer.to_hex(), payload.to_hex());
    assert_eq!(Some(tx_id), dca.tx_collateral.tx_hash);
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
    assert_eq!(buffer.to_hex(), payload.to_hex());
}

#[test]
pub fn test_coinjoin_final_transaction() {
    // CoinJoinFinalTransaction(msgSessionID=512727, transaction=a57015f0f8c85cdee8ab47d9bb7792c23c21bfbad1a19b7b4368915ba970fae1)
    let payload = Vec::from_hex("d7d20700020000000424e55da190e79da9540b0fc87e859261e4a2a33530a005cab68f5cd3ece0234a0200000000fffffffff7b9fdaf651dc308b6f538ac9dae090268f08f424fd91c705fe5d12174999f5d0400000000ffffffff20d63b2ca93309e3526cac6fab31545bd932ba705e7011e720ba69af59baaba10000000000ffffffff20d63b2ca93309e3526cac6fab31545bd932ba705e7011e720ba69af59baaba10300000000ffffffff044a420f00000000001976a914257b0482306f29fe7d97fb8b847746ba4a1606e588ac4a420f00000000001976a9146662e6130b7b1f06778ae1e24b687db752e1a83d88ac4a420f00000000001976a914ac2faba75d50cdd8dff86b8a457c45201aefb96f88ac4a420f00000000001976a914b89ab9894c767e22e85e2164b9f65fc0a4c3dc7e88ac00000000").unwrap();
    let tx_id = UInt256::from_hex("a57015f0f8c85cdee8ab47d9bb7792c23c21bfbad1a19b7b4368915ba970fae1").unwrap().reversed();
   
    let mut cursor = Cursor::new(&payload);
    let dsf = CoinJoinFinalTransaction::consensus_decode(&mut cursor).unwrap();
    
    let tx_hash = dsf.tx.tx_hash;
    let from_ctor = CoinJoinFinalTransaction {
        msg_session_id: 512727, 
        tx: dsf.tx
    };
    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(512727, dsf.msg_session_id);
    assert_eq!(Some(tx_id), tx_hash);
    assert_eq!(buffer.to_hex(), payload.to_hex());
}

#[test]
pub fn test_coinjoin_status_update_from_payload() {
    // CoinJoinStatusUpdate(sessionID=783283, state=POOL_STATE_QUEUE, statusUpdate=STATUS_REJECTED, messageID=ERR_DENOM)
    let mut payload = Vec::from_hex("b3f30b00010000000000000001000000").unwrap();
    // let mut payload = Vec::from_hex("b3f30b0001000000000000000000000001000000").unwrap(); // TODO: versioning (BLS_LEGACY payload)
   
    let mut cursor = Cursor::new(&payload);
    let mut dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(783283, dssu.session_id);
    assert_eq!(PoolState::PoolStateQueue, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::StatusRejected, dssu.status_update);
    assert_eq!(PoolMessage::ErrDenom, dssu.message_id);

    payload = Vec::from_hex("d7d20700030000000100000013000000").unwrap();
    // payload = Vec::from_hex("d7d2070003000000000000000100000013000000").unwrap(); // TODO: versioning (BLS_LEGACY payload)
   
    cursor = Cursor::new(&payload);
    dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(512727, dssu.session_id);
    assert_eq!(PoolState::PoolStateSigning, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::StatusAccepted, dssu.status_update);
    assert_eq!(PoolMessage::MsgNoErr, dssu.message_id);
}

#[test]
pub fn test_coinjoin_status_update_from_ctor() {
    let payload = Vec::from_hex("5faa0c00010000000100000013000000").unwrap();
    // let mut payload = Vec::from_hex("5faa0c0001000000000000000100000013000000").unwrap(); // TODO: versioning (BLS_LEGACY payload)
   
    let mut cursor = Cursor::new(&payload);
    let dssu = CoinJoinStatusUpdate::consensus_decode(&mut cursor).unwrap();

    assert_eq!(830047, dssu.session_id);
    assert_eq!(PoolState::PoolStateQueue, dssu.pool_state);
    assert_eq!(PoolStatusUpdate::StatusAccepted, dssu.status_update);
    assert_eq!(PoolMessage::MsgNoErr, dssu.message_id);
   
    let from_ctor = CoinJoinStatusUpdate {
        session_id: 830047,
        pool_state: PoolState::PoolStateQueue,
        status_update: PoolStatusUpdate::StatusAccepted,
        message_id: PoolMessage::MsgNoErr
    };

    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(buffer.to_hex(), payload.to_hex());
}