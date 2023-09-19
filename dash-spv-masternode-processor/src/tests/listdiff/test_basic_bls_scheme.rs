use bls_signatures::G1Element;
use hashes::hex::FromHex;
use crate::chain::common::ChainType;
use crate::crypto::UInt384;
use crate::models::OperatorPublicKey;

#[test]
fn test_legacy_basic_conversion() {
    let chain_type = ChainType::TestNet;
    let block_height = 530000;
    let legacy_key = OperatorPublicKey {
        data: UInt384::from_hex("16ca29d03ef4897a22fe467bb58c52448c63bb29534502305e8ff142ac03907fae0851ff2528e4878ef51bfa3d5a1f22").unwrap(),
        version: 1
    };
    let basic_key = OperatorPublicKey {
        data: UInt384::from_hex("96ca29d03ef4897a22fe467bb58c52448c63bb29534502305e8ff142ac03907fae0851ff2528e4878ef51bfa3d5a1f22").unwrap(),
        version: 2,
    };
    assert_eq!(UInt384(*G1Element::from_bytes(&basic_key.data.0).unwrap().serialize_legacy()), legacy_key.data);

    let bk1 = UInt384::from_hex("981ab9848a9eba75643cde7f3ae8c2d3ba1efe36ba9dbbd2162437780f35493f9ed327220a5a0e60d5ae2793f5a75525").unwrap();
    println!("{}", UInt384(*G1Element::from_bytes(&bk1.0).unwrap().serialize_legacy()));
    // println!("{}", UInt384(*G1Element::from_bytes(&bk1.0).unwrap().serialize()));
    // println!("{}", UInt384(*G1Element::from_bytes_legacy(&bk1.0).unwrap().serialize()));
    println!("{}", UInt384(*G1Element::from_bytes_legacy(&bk1.0).unwrap().serialize_legacy()));

    let bk1 = UInt384::from_hex("158367af44572fbd35b475ca6259e1c499eefcbd5573ded52917c45cd2c8a0aa2e4ac9fd25ecdf1ef548750d2caf3ee3").unwrap();
    // println!("{}", UInt384(*G1Element::from_bytes(&bk1.0).unwrap().serialize_legacy()));
    // println!("{}", UInt384(*G1Element::from_bytes(&bk1.0).unwrap().serialize()));
    println!("{}", UInt384(*G1Element::from_bytes_legacy(&bk1.0).unwrap().serialize()));
    println!("{}", UInt384(*G1Element::from_bytes_legacy(&bk1.0).unwrap().serialize_legacy()));


}
