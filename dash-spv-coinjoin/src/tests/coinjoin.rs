use std::ffi::c_void;
use std::{collections::HashMap, io::Cursor};
use dash_spv_masternode_processor::types;
use dash_spv_masternode_processor::{hashes::hex::FromHex, consensus::Decodable};
use dash_spv_masternode_processor::tx::transaction::Transaction;
use ferment_interfaces::unbox_any;

use crate::ffi::input_value::InputValue;
use crate::models::denominations::Denomination;
use crate::coinjoin::CoinJoin;

#[test]
pub fn test_coinjoin() {
    let smallest = CoinJoin::get_smallest_denomination();
    assert_eq!(100001, smallest);
}

struct DenomTest {
    amount: u64,
    is_denomination: bool,
    string_value: String,
}

#[test]
fn standard_denomination_test() {
    let tests = vec![
        DenomTest { amount: 1000010000, is_denomination: true, string_value: "10.0001".to_string() },
        DenomTest { amount: 100001000, is_denomination: true, string_value: "1.00001".to_string() },
        DenomTest { amount: 10000100, is_denomination: true, string_value: "0.100001".to_string() },
        DenomTest { amount: 1000010, is_denomination: true, string_value: "0.0100001".to_string() },
        DenomTest { amount: 100001, is_denomination: true, string_value: "0.00100001".to_string() },
        DenomTest { amount: 10000, is_denomination: false, string_value: "N/A".to_string() },
        DenomTest { amount: 20000, is_denomination: false, string_value: "N/A".to_string() },
        DenomTest { amount: 1000, is_denomination: false, string_value: "N/A".to_string() },
        DenomTest { amount: 546, is_denomination: false, string_value: "N/A".to_string() },
        DenomTest { amount: 1000000000, is_denomination: false, string_value: "N/A".to_string() },
    ];

    for test in tests.iter() {
        assert_eq!(test.is_denomination, CoinJoin::is_denominated_amount(test.amount));
        assert_eq!(test.string_value, CoinJoin::denomination_to_string(CoinJoin::amount_to_denomination(test.amount)));
    }

    assert_eq!(100001, CoinJoin::get_smallest_denomination());

    for value in CoinJoin::get_standard_denominations().iter() {
        assert_eq!(*value as i64, CoinJoin::denomination_to_amount(CoinJoin::amount_to_denomination(*value)));
    }

    let denomination_list = Denomination::all_values();
    for denomination in denomination_list.iter() {
        let pos = CoinJoin::get_standard_denominations().iter().position(|&x| x == *denomination);
        assert_ne!(None, pos);
    }
}

#[test]
fn test_collateral() {
    let good_collateral_values = vec![10000, 12345, 32123, 19000];
    let bad_collateral_values = vec![9999, 40001, 100000, 100001];

    for value in good_collateral_values.iter() {
        assert!(CoinJoin::is_collateral_amount(*value));
    }

    for value in bad_collateral_values.iter() {
        assert!(!CoinJoin::is_collateral_amount(*value));
    }
}

#[test]
fn rounds_string_test() {
    let mut map = HashMap::new();
    map.insert(0, "coinjoin");
    map.insert(16, "coinjoin");
    map.insert(-4, "bad index");
    map.insert(-3, "collateral");
    map.insert(-2, "non-denominated");
    map.insert(-1, "no such tx");

    for (rounds, expected_str) in map {
        assert_eq!(expected_str, CoinJoin::get_rounds_string(rounds));
    }
}

#[test]
fn is_collateral_valid_test() {
    let payload = Vec::from_hex("0100000001cb1768cae4d44860a6ae18fec6d81f14fa84de48f0027a83107889671c1f1d54000000006a47304402202edab2fb737f7672bd9898e00855a86ca3bdc60a676a16766edb505370e9e0d50220139fd47f674e2ccee32139cf7a82e441f6f2c7d79d7135ac900a3a836591ae9301210262ffa9b2c936262abd869ead9cfde301d29adbe3d4b18d8cd6a150d45e61d656ffffffff0130750000000000001976a914d1a0b93ec28bba201c03fb01a934727782c7b9e288ac00000000").unwrap();
    let mut cursor = Cursor::new(&payload);
    let tx = Transaction::consensus_decode(&mut cursor).unwrap();

    let coinjoin = CoinJoin::new(
        good_input_value,
        has_chain_lock,
        destroy_input_value,
        std::ptr::null()
    );

    assert!(coinjoin.is_collateral_valid(&tx, true));

    let coinjoin = CoinJoin::new(
        bad_input_value,
        has_chain_lock,
        destroy_input_value,
        std::ptr::null()
    );

    assert!(!coinjoin.is_collateral_valid(&tx, true));
}

extern "C" fn good_input_value(
    _prevout_hash: *mut [u8; 32],
    _index: u32,
    _context: *const c_void,
) -> *mut InputValue {
    Box::into_raw(Box::new(InputValue { is_valid: true, value: 40000 }))
}

extern "C" fn bad_input_value(
    _prevout_hash: *mut [u8; 32],
    _index: u32,
    _context: *const c_void,
) -> *mut InputValue {
    Box::into_raw(Box::new(InputValue { is_valid: true, value: 10000 }))
}

extern "C" fn has_chain_lock(
    _block: *mut types::Block,
    _context: *const c_void,
) -> bool {
    true
}

unsafe extern "C" fn destroy_input_value(input_value: *mut InputValue) {
    let _res = unbox_any(input_value);
}

// TODO: byte[] txPayload = Utils.HEX.decode("0100000001cb1768cae4d44860a6ae18fec6d81f14fa84de48f0027a83107889671c1f1d54000000006a47304402202edab2fb737f7672bd9898e00855a86ca3bdc60a676a16766edb505370e9e0d50220139fd47f674e2ccee32139cf7a82e441f6f2c7d79d7135ac900a3a836591ae9301210262ffa9b2c936262abd869ead9cfde301d29adbe3d4b18d8cd6a150d45e61d656ffffffff0130750000000000001976a914d1a0b93ec28bba201c03fb01a934727782c7b9e288ac00000000");
//         Transaction txCollateral = new Transaction(PARAMS, txPayload);
