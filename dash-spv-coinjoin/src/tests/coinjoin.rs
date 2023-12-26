use crate::coinjoin::CoinJoin;

#[test]
pub fn test_coinjoin() {
    let smallest = CoinJoin::get_smallest_denomination();
    assert_eq!(100001, smallest);
}