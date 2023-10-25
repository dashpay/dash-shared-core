use hashes::hex::{FromHex, ToHex};
use crate::crypto::byte_util::{BytesDecodable, Reversable};
use crate::crypto::UInt256;
use crate::tx::CoinbaseTransaction;

#[test]
pub fn test_coinbase_tx() {
    let bytes = Vec::from_hex("03000500010000000000000000000000000000000000000000000000000000000000000000ffffffff0502f6050105ffffffff0200c11a3d050000002321038df098a36af5f1b7271e32ad52947f64c1ad70c16a8a1a987105eaab5daa7ad2ac00c11a3d050000001976a914bfb885c89c83cd44992a8ade29b610e6ddf00c5788ac00000000260100f6050000aaaec8d6a8535a01bd844817dea1faed66f6c397b1dcaec5fe8c5af025023c35").unwrap();
    let tx = CoinbaseTransaction::from_bytes(&bytes, &mut 0).unwrap();
    assert_eq!(tx.to_data().to_hex(), bytes.to_hex(), "Coinbase transaction does not match it's data");
    assert_eq!(tx.base.tx_hash, Some(UInt256::from_hex("5b4e5e99e967e01e27627621df00c44525507a31201ceb7b96c6e1a452e82bef").unwrap().reversed()), "Coinbase transaction hash does not match it's data dash");
}