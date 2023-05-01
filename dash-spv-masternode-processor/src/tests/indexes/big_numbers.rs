use crate::crypto::UInt256;

#[test]
pub fn test_superior_and_equal_uint256() {
    let big_a = UInt256::from(7u64);
    let big_b = UInt256::from(5u64);
    assert!(big_a.sup(&big_b), "A in uint 256 needs to be bigger than B");
    let big_c = UInt256::from([0,1,0,0]);
    assert!(big_c.sup(&big_a), "C in uint 256 needs to be bigger than A");
    let d: u64 = 1 << 30;
    let big_d = UInt256::from(d);
    let big_d_left_shifted = big_d.shift_left_le(34);
    assert!(big_c.eq(&big_d_left_shifted), "C and D should be equal");
    let e: u32 = 1 << 30;
    let big_e = UInt256::from(e);
    let big_e_left_shifted = big_e.shift_left_le(34);
    assert!(big_e_left_shifted.eq(&big_d_left_shifted), "D and E should be equal");
}

#[test]
pub fn test_biguints_ops() {
    let mut x = [0u8; 32];
    x[0] = 0x32; // 50
    let a = UInt256(x);
    for i in 0..=32 {
        println!("{}", a >> i);
    }

    let a = b"a0fcffffffffffffffffffffffffffffffffffffffffffffffffffffff4ffbff";
    let b = b"100e000000000000000000000000000000000000000000000000000000000000";

}

