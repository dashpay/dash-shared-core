use bls_signatures::G1Element;
use dashcore::hashes::hex::FromHex;
use dashcore::secp256k1::hashes::hex::DisplayHex;
use dash_spv_crypto::crypto::byte_util::Zeroable;
use dash_spv_crypto::keys::{BLSKey, OperatorPublicKey};
use dash_spv_crypto::network::ChainType;

#[test]
fn test_legacy_basic_conversion() {
    let chain_type = ChainType::TestNet;
    let block_height = 530000;
    let legacy_key = OperatorPublicKey {
        data: <[u8; 48]>::from_hex("16ca29d03ef4897a22fe467bb58c52448c63bb29534502305e8ff142ac03907fae0851ff2528e4878ef51bfa3d5a1f22").unwrap(),
        version: 1
    };
    let basic_key = OperatorPublicKey {
        data: <[u8; 48]>::from_hex("96ca29d03ef4897a22fe467bb58c52448c63bb29534502305e8ff142ac03907fae0851ff2528e4878ef51bfa3d5a1f22").unwrap(),
        version: 2,
    };
    assert_eq!(*G1Element::from_bytes(&basic_key.data).unwrap().serialize_legacy(), legacy_key.data);
    let bk1 = <[u8; 48]>::from_hex("981ab9848a9eba75643cde7f3ae8c2d3ba1efe36ba9dbbd2162437780f35493f9ed327220a5a0e60d5ae2793f5a75525").unwrap();
    println!("{}", G1Element::from_bytes(&bk1).unwrap().serialize_legacy().to_lower_hex_string());
    println!("{}", G1Element::from_bytes_legacy(&bk1).unwrap().serialize_legacy().to_lower_hex_string());
    let bk1 = <[u8; 48]>::from_hex("158367af44572fbd35b475ca6259e1c499eefcbd5573ded52917c45cd2c8a0aa2e4ac9fd25ecdf1ef548750d2caf3ee3").unwrap();
    println!("{}", G1Element::from_bytes_legacy(&bk1).unwrap().serialize().to_lower_hex_string());
    println!("{}", G1Element::from_bytes_legacy(&bk1).unwrap().serialize_legacy().to_lower_hex_string());


}
#[test]
fn test_bls_migration() {
    let chain_type = ChainType::TestNet;
    let bytes = Vec::from_hex("0000000104971efda88000000399eb1756922d7c107de051561deb0104612b6e96d273606c4277d7700f5f5a380bac7e5f4adc010f59973fc637cb7aed41ac52771a58c1f7c0978067be0ab44cf4b60d95ae9bdfe2e35d06f83cff7fbc").unwrap();
    match BLSKey::migrate_from_legacy_extended_public_key_data(&bytes) {
        Ok(key) => {
            assert!(key.seckey.is_zero());
            assert_eq!(key.pubkey.to_lower_hex_string(), "8bac7e5f4adc010f59973fc637cb7aed41ac52771a58c1f7c0978067be0ab44cf4b60d95ae9bdfe2e35d06f83cff7fbc");
            assert_eq!(key.chaincode.to_lower_hex_string(), "99eb1756922d7c107de051561deb0104612b6e96d273606c4277d7700f5f5a38");
            assert_eq!(key.extended_public_key_data.to_lower_hex_string(), "0000000104971efda88000000399eb1756922d7c107de051561deb0104612b6e96d273606c4277d7700f5f5a388bac7e5f4adc010f59973fc637cb7aed41ac52771a58c1f7c0978067be0ab44cf4b60d95ae9bdfe2e35d06f83cff7fbc");
            assert!(!key.use_legacy);
        },
        Err(err) => panic!("Can't migrate bls key from extended public key data: {err}")
    }
}
