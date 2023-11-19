use dash_spv_masternode_processor::chain::common::ChainType;
use crate::tests::common::assert_diff_chain;

// #[test]
fn test_core19rc10() {
    // 85.209.243.24 (/Dash Core:18.2.1/ protocol 70227)
    assert_diff_chain(
        ChainType::TestNet,
        &["MNT530000.dat", "MNL_530000_867700__70227.dat"],
        &[],
        None);
}

// #[test]
fn test_core19_70227() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNT530000.dat", "MNL_530000_868321__70227.dat"],
        &[],
        None);
}

// #[test]
fn test_mnlistdiff_and_qrinfo_core19() {
    assert_diff_chain(
        ChainType::TestNet,
        &[
            "MNL_0_868888__70227.dat",
            "MNL_0_869464__70227.dat",
            "MNL_0_869760__70227.dat",
            "MNL_868888_869176__70227.dat",
            "MNL_869176_869464__70227.dat",
            "MNL_869464_869752__70227.dat",
            "MNL_869752_869760__70227.dat",
            "MNL_869760_869761__70227.dat",
            "MNL_869761_869762__70227.dat",
            "MNL_869762_869763__70227.dat",
            "MNL_869763_869764__70227.dat",
            "MNL_869764_869765__70227.dat",
            "MNL_869765_869766__70227.dat",
            "MNL_869766_869767__70227.dat",
            "MNL_869767_869768__70227.dat",
            "MNL_869768_869769__70227.dat",
            "MNL_869769_869770__70227.dat",
            "MNL_869770_869771__70227.dat",
            "MNL_869771_869772__70227.dat",
            "MNL_869772_869773__70227.dat",
            "MNL_869773_869774__70227.dat",
            "MNL_869774_869775__70227.dat",
            "MNL_869775_869776__70227.dat",
            "MNL_869776_869777__70227.dat",
            "MNL_869777_869778__70227.dat",
            "MNL_869778_869779__70227.dat",
            "MNL_869779_869780__70227.dat",
            "MNL_869780_869781__70227.dat",
            "MNL_869781_869782__70227.dat",
            "MNL_869782_869783__70227.dat",
            "MNL_869783_869784__70227.dat",
            "MNL_869784_869785__70227.dat",
            "MNL_869785_869786__70227.dat",
            "MNL_869786_869787__70227.dat",
            "MNL_869787_869788__70227.dat",
            "MNL_869788_869789__70227.dat",
            "MNL_869789_869790__70227.dat",
            "MNL_869790_869791__70227.dat",
        ],
        &[
            "QRINFO_0_870235__70227.dat"
        ],
        None);
}

#[test]
fn test_core19_2() {
    assert_diff_chain(
        ChainType::TestNet,
        &["MNL_0_530000__70228.dat", "MNL_530000_852596__70228.dat"],
        &[],
        None);
}
