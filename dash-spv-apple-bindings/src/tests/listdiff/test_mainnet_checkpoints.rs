use dash_spv_crypto::network::ChainType;
use crate::tests::common::assert_diff_chain;

#[test]
fn testnet_checkpoint_530000() {
    assert_diff_chain(ChainType::TestNet, &["MNT530000.dat"], &[], None, false);
}

#[test]
fn mainnet_checkpoint_1720000() {
    /*{
        1720000,
        "000000000000001ef1f8a3d33bbe304c1d12f59f2c8aa989099dc215fd10903e",
        1660295895,
        0x19362176u,
        "ML1720000",
        "67c6348c35bc42aa4cabd25e29560f5d22c6a9fba274bf0c52fe73021d0e8d5e",
        "000000000000000000000000000000000000000000007715a9ae4dd7ff1d3902"
    }*/
    assert_diff_chain(ChainType::MainNet, &["ML1720000.dat"], &[], None, false);
}
