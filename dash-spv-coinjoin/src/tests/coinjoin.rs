use std::collections::HashMap;
use crate::{coinjoin::CoinJoin, models::Denomination};

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

// TODO: isCollateralValidTest