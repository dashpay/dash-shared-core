use std::io::Cursor;
use dash_spv_masternode_processor::hashes::hex::{FromHex, ToHex};
use dash_spv_masternode_processor::crypto::{byte_util::Reversable, UInt256};
use dash_spv_masternode_processor::consensus::{Decodable, Encodable};
use crate::models::tx_outpoint::TxOutPoint;

#[test]
pub fn test_transaction_outpoint_payload() {
    let hex = "e2f910eb47e2dde768b9f89e1a84607ac559c0f9628ff0b44b49de0a92e5b0ce00000000";
    let outpoint_data = Vec::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(&outpoint_data);
    let outpoint = TxOutPoint::consensus_decode(&mut cursor).unwrap();

    let hash = UInt256::from_hex("ceb0e5920ade494bb4f08f62f9c059c57a60841a9ef8b968e7dde247eb10f9e2").unwrap().reversed();

    assert_eq!(hash, outpoint.hash);
    assert_eq!(0, outpoint.index);

    let from_ctor = TxOutPoint { hash, index: 0 };
    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(hash, outpoint.hash);
    assert_eq!(hex, buffer.to_hex());
}