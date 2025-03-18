use std::io::Cursor;
use dashcore::hashes::hex::FromHex;
use dashcore::{OutPoint, Txid};
use dashcore::consensus::{Decodable, Encodable};
use dashcore::prelude::DisplayHex;

#[test]
pub fn test_transaction_outpoint_payload() {
    let hex = "e2f910eb47e2dde768b9f89e1a84607ac559c0f9628ff0b44b49de0a92e5b0ce00000000";
    let outpoint_data = Vec::from_hex(hex).unwrap();
    let mut cursor = Cursor::new(&outpoint_data);
    let outpoint = OutPoint::consensus_decode(&mut cursor).unwrap();

    let hash = Txid::from_hex("ceb0e5920ade494bb4f08f62f9c059c57a60841a9ef8b968e7dde247eb10f9e2").unwrap();
    // let hash = <[u8; 32]>::from_hex("ceb0e5920ade494bb4f08f62f9c059c57a60841a9ef8b968e7dde247eb10f9e2").unwrap().reversed();

    assert_eq!(hash, outpoint.txid);
    assert_eq!(0, outpoint.vout);

    let from_ctor = OutPoint { txid: Txid::from(hash), vout: 0 };
    let mut buffer = Vec::new();
    from_ctor.consensus_encode(&mut buffer).unwrap();

    assert_eq!(hash, outpoint.txid);
    assert_eq!(hex, buffer.to_lower_hex_string());
}