use dash_spv_masternode_processor::chain::common::ChainType;
use dash_spv_masternode_processor::crypto::UInt256;
use crate::ffi::from::FromFFI;
use crate::tests::common::{assert_diff_result, create_default_context, process_mnlistdiff, process_qrinfo, register_cache, register_default_processor, register_logger};

// #[test]
fn test_core19rc10() {
    // 85.209.243.24 (/Dash Core:18.2.1/ protocol 70227)
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let result = process_mnlistdiff(chain.load_message("MNT530000.dat"), processor, context, 70219, false, true);
    let result = unsafe { &*result };
    assert_diff_result(context, result);
    unsafe {
        context.cache.mn_lists.insert(UInt256(*result.block_hash), (*result.masternode_list).decode());
    }
    // let result = process_mnlistdiff(message_from_file("MNL_530000_867700.dat".to_string()), processor, context, 70227);
    let result = process_mnlistdiff(chain.load_message("MNL_530000_867700.dat"), processor, context, 70227, false, true);
    // let result = process_mnlistdiff(message_from_file("MNL_530000_867700.dat".to_string()), processor, context, 70227);
    assert_diff_result(context, unsafe { &*result });
}

// #[test]
fn test_core19_70224() {
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let result = process_mnlistdiff(chain.load_message("MNT530000.dat"), processor, context, 70219, false, true);
    let result = unsafe { &*result };
    assert_diff_result(context, result);
    unsafe {
        context.cache.mn_lists.insert(UInt256(*result.block_hash), (*result.masternode_list).decode());
    }
    let result = process_mnlistdiff(chain.load_message("MNL_530000_868301.dat"), processor, context, 70224, false, true);
    // let result = process_mnlistdiff(message_from_file("MNL_530000_868301.dat"), processor, context, 70227);
    assert_diff_result(context, unsafe { &*result });
}

// #[test]
fn test_core19_70227() {
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let result = unsafe { &*process_mnlistdiff(chain.load_message("MNT530000.dat"), processor, context, 70219, false, true) };
    // assert_diff_result(context, result);
    unsafe {
        let list = (*result.masternode_list).decode();
        context.cache.mn_lists.insert(UInt256(*result.block_hash), list);
    }
    let result = process_mnlistdiff(chain.load_message("MNL_530000_868321.dat"), processor, context, 70227, false, true);
    assert_diff_result(context, unsafe { &*result });
}

// #[test]
fn test_mnlistdiff_and_qrinfo_core19() {
    register_logger();
    let version = 70227;
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let diffs = vec![
        "MNL_0_868888.dat",
        "MNL_0_869464.dat",
        "MNL_0_869760.dat",
        "MNL_868888_869176.dat",
        "MNL_869176_869464.dat",
        "MNL_869464_869752.dat",
        "MNL_869752_869760.dat",
        "MNL_869760_869761.dat",
        "MNL_869761_869762.dat",
        "MNL_869762_869763.dat",
        "MNL_869763_869764.dat",
        "MNL_869764_869765.dat",
        "MNL_869765_869766.dat",
        "MNL_869766_869767.dat",
        "MNL_869767_869768.dat",
        "MNL_869768_869769.dat",
        "MNL_869769_869770.dat",
        "MNL_869770_869771.dat",
        "MNL_869771_869772.dat",
        "MNL_869772_869773.dat",
        "MNL_869773_869774.dat",
        "MNL_869774_869775.dat",
        "MNL_869775_869776.dat",
        "MNL_869776_869777.dat",
        "MNL_869777_869778.dat",
        "MNL_869778_869779.dat",
        "MNL_869779_869780.dat",
        "MNL_869780_869781.dat",
        "MNL_869781_869782.dat",
        "MNL_869782_869783.dat",
        "MNL_869783_869784.dat",
        "MNL_869784_869785.dat",
        "MNL_869785_869786.dat",
        "MNL_869786_869787.dat",
        "MNL_869787_869788.dat",
        "MNL_869788_869789.dat",
        "MNL_869789_869790.dat",
        "MNL_869790_869791.dat",
    ].iter().for_each(|name| {
        let result = process_mnlistdiff(chain.load_message(name), processor, context, version, false, true);
        assert_diff_result(context, unsafe { &*result });
    });
    context.is_dip_0024 = true;
    let result = process_qrinfo(chain.load_message("QRINFO_0_870235.dat"), processor, context, version, false, true);
    let result = unsafe { &*result };
    assert_diff_result(context, unsafe { &*result.result_at_h_4c });
    assert_diff_result(context, unsafe { &*result.result_at_h_3c });
    assert_diff_result(context, unsafe { &*result.result_at_h_2c });
    assert_diff_result(context, unsafe { &*result.result_at_h_c });
    //assert_diff_result(context, unsafe { *result.result_at_h });
    assert_diff_result(context, unsafe { &*result.result_at_tip });
}

// #[test]
fn test_qrinfo_core19() {
    register_logger();
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, true, cache);
    let processor = register_default_processor(context);
    let result = process_qrinfo(chain.load_message("QRINFO_0_870235.dat"), processor, context, 70227, false, true);
    let result = unsafe { &*result };
    assert_diff_result(context, unsafe { &*result.result_at_h_4c });
    assert_diff_result(context, unsafe { &*result.result_at_h_3c });
    assert_diff_result(context, unsafe { &*result.result_at_h_2c });
    assert_diff_result(context, unsafe { &*result.result_at_h_c });
    assert_diff_result(context, unsafe { &*result.result_at_h });
    assert_diff_result(context, unsafe { &*result.result_at_tip });

}


//#[test]
fn test_verify_25_67() {
    register_logger();
    let version = 70227;
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let result = process_mnlistdiff(chain.load_message("MNL_0_871104.dat"), processor, context, version, false, true);
    assert_diff_result(context, unsafe { &*result });
    let result = process_mnlistdiff(chain.load_message("MNL_0_874011.dat"), processor, context, version, false, true);
    // assert_diff_result(context, result);
}

// #[test]
// fn test_verify_chained_rotation() {
//     register_logger();
//     let version = 70227;
//     let cache = register_cache();
//     let context = &mut create_default_context(ChainType::TestNet, false, cache);
//     let processor = register_default_processor();
//     let diffs = vec![
//         "MNL_0_870600.dat",
//         "MNL_870600_870624.dat",
//         "MNL_870624_870648.dat",
//         "MNL_870648_870672.dat",
//         "MNL_870672_870696.dat",
//         "MNL_870696_870720.dat",
//         "MNL_870720_870744.dat",
//         "MNL_870744_870768.dat",
//         "MNL_870768_870792.dat",
//         "MNL_870792_870816.dat",
//         "MNL_870816_870840.dat",
//         "MNL_870840_870864.dat",
//         "MNL_870864_870888.dat",
//         "MNL_870888_870912.dat",
//         "MNL_870912_870936.dat",
//         "MNL_870936_870960.dat",
//         "MNL_870960_870984.dat",
//         "MNL_870984_871008.dat",
//         "MNL_871008_871032.dat",
//         "MNL_871032_871056.dat",
//         "MNL_871056_871080.dat",
//         "MNL_871080_871104.dat",
//         "MNL_871104_871128.dat",
//         "MNL_871128_871152.dat",
//         "MNL_871152_874488.dat",
//         "MNL_874488_874512.dat",
//         "MNL_874512_874536.dat",
//         "MNL_874536_874560.dat",
//         "MNL_874560_874584.dat",
//         "MNL_874584_874608.dat",
//         "MNL_874608_874632.dat",
//         "MNL_874632_874656.dat",
//         "MNL_874656_874680.dat",
//         "MNL_874680_874704.dat",
//         "MNL_874704_874728.dat",
//         "MNL_874728_874752.dat",
//         "MNL_874752_874776.dat",
//         "MNL_874776_874800.dat",
//         "MNL_874800_874824.dat",
//         "MNL_874824_874848.dat",
//         "MNL_874848_874872.dat",
//         "MNL_874872_874896.dat",
//         "MNL_874896_874920.dat",
//         "MNL_874920_874944.dat",
//         "MNL_874944_874968.dat",
//         "MNL_874968_874992.dat",
//         "MNL_874992_875016.dat",
//         "MNL_875016_875040.dat",
//         "MNL_875040_875064.dat",
//         "MNL_875064_875088.dat",
//         "MNL_875088_875112.dat",
//         "MNL_875112_875136.dat",
//         "MNL_875136_875160.dat",
//         "MNL_875160_875184.dat",
//         "MNL_875184_875208.dat",
//         "MNL_875208_875241.dat",
//         "MNL_875241_875242.dat"
//     ].iter().for_each(|name| {
//         let result = process_mnlistdiff(message_from_file(format!("testnet/{}", name).as_str()), processor, context, version, false, true);
//         assert_diff_result(context, result);
//     });
//     context.is_dip_0024 = true;
//     let result = process_qrinfo(message_from_file("testnet/QRINFO_0_875241.dat"), processor, context, version, false, true);
//     assert_diff_result(context, unsafe { *result.result_at_h_4c });
//     assert_diff_result(context, unsafe { *result.result_at_h_3c });
//     assert_diff_result(context, unsafe { *result.result_at_h_2c });
//     assert_diff_result(context, unsafe { *result.result_at_h_c });
//     assert_diff_result(context, unsafe { *result.result_at_h });
//     assert_diff_result(context, unsafe { *result.result_at_tip });
//
//     let result = process_qrinfo(message_from_file("testnet/QRINFO_875241_875242.dat"), processor, context, version, false, true);
//     assert_diff_result(context, unsafe { *result.result_at_h_4c });
//     assert_diff_result(context, unsafe { *result.result_at_h_3c });
//     assert_diff_result(context, unsafe { *result.result_at_h_2c });
//     assert_diff_result(context, unsafe { *result.result_at_h_c });
//     assert_diff_result(context, unsafe { *result.result_at_h });
//     assert_diff_result(context, unsafe { *result.result_at_tip });
// }
//
// #[test]
// fn test_verify_chained_rotation2() {
//     register_logger();
//     let version = 70227;
//     let cache = register_cache();
//     let context = &mut create_default_context(ChainType::TestNet, false, cache);
//     let processor = register_default_processor();
//     context.is_dip_0024 = true;
//     let result = process_qrinfo(message_from_file("testnet/QRINFO_0_888537.dat"), processor, context, version, false, true);
//     assert_diff_result(context, unsafe { *result.result_at_h_4c });
//     assert_diff_result(context, unsafe { *result.result_at_h_3c });
//     assert_diff_result(context, unsafe { *result.result_at_h_2c });
//     assert_diff_result(context, unsafe { *result.result_at_h_c });
//     assert_diff_result(context, unsafe { *result.result_at_h });
//     assert_diff_result(context, unsafe { *result.result_at_tip });
// }
//
// #[test]
// fn test_verify_chained_rotation3() {
//     register_logger();
//     let version = 70227;
//     let cache = register_cache();
//     let context = &mut create_default_context(ChainType::TestNet, false, cache);
//     let processor = register_default_processor();
//     let diffs = vec![
//         "MNL_0_888192.dat",
//         "MNL_888192_888193.dat",
//         "MNL_888193_888194.dat",
//         "MNL_888194_888195.dat",
//         "MNL_888195_888196.dat",
//         "MNL_888196_888197.dat",
//         "MNL_888197_888198.dat",
//         "MNL_888198_888199.dat",
//         "MNL_888199_888200.dat",
//         "MNL_888200_888201.dat",
//         "MNL_888201_888202.dat",
//         "MNL_888202_888203.dat",
//         "MNL_888203_888204.dat",
//         "MNL_888204_888205.dat",
//         "MNL_888205_888206.dat",
//         "MNL_888206_888207.dat",
//         "MNL_888207_888208.dat",
//         "MNL_888208_888209.dat",
//         "MNL_888209_888210.dat",
//         "MNL_888210_888211.dat",
//         "MNL_888211_888212.dat",
//         "MNL_888212_888213.dat",
//         "MNL_888213_888214.dat",
//         "MNL_888214_888215.dat",
//         "MNL_888215_888216.dat",
//         "MNL_888216_888217.dat",
//         "MNL_888217_888218.dat",
//         "MNL_888218_888219.dat",
//         "MNL_888219_888220.dat",
//         "MNL_888220_888221.dat",
//         "MNL_888221_888222.dat",
//         "MNL_888222_888223.dat",
//       ].iter().for_each(|name| {
//         let result = process_mnlistdiff(message_from_file(format!("testnet/{}", name).as_str()), processor, context, version, false, true);
//         assert_diff_result(context, result);
//     });
//
//     context.is_dip_0024 = true;
//     let result = process_qrinfo(message_from_file("testnet/QRINFO_0_888655.dat"), processor, context, version, false, true);
//     assert_diff_result(context, unsafe { *result.result_at_h_4c });
//     assert_diff_result(context, unsafe { *result.result_at_h_3c });
//     assert_diff_result(context, unsafe { *result.result_at_h_2c });
//     assert_diff_result(context, unsafe { *result.result_at_h_c });
//     assert_diff_result(context, unsafe { *result.result_at_h });
//     assert_diff_result(context, unsafe { *result.result_at_tip });
// }


#[test]
fn test_core19_2() {
    register_logger();
    let protocol_version = 70228;
    let chain = ChainType::TestNet;
    let cache = register_cache();
    let context = &mut create_default_context(chain, false, cache);
    let processor = register_default_processor(context);
    let diffs = vec![
        "MNL_0_530000_70228.dat",
        "MNL_530000_852596.dat",
    ].iter().for_each(|filename| {
        let result = process_mnlistdiff(chain.load_message(filename), processor, context, protocol_version, false, true);
        assert_diff_result(context, unsafe { &*result });
    });
}
