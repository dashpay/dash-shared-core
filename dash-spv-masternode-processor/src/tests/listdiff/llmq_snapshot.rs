use byte::BytesExt;
use hashes::hex::FromHex;
use crate::crypto::byte_util::BytesDecodable;
use crate::crypto::data_ops::Data;
use crate::{common, models};
use crate::models::LLMQSnapshot;

#[test]
pub fn test_quorum_snapshot() {
    let payload = Vec::from_hex("000000001fb95e7b0300").unwrap();
    let snapshot = models::LLMQSnapshot::from_bytes(payload.as_slice(), &mut 0).unwrap();
    println!("snapshot: {:?}", snapshot);
    // as slice
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(0));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(1));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(2));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(3));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(4));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(5));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(6));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(7));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(8));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(9));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(10));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(11));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(12));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(13));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(14));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(15));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(16));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(17));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(18));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(19));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(20));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(21));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(22));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(23));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(24));
    assert!(snapshot.member_list.as_slice().bit_is_true_at_le_index(25));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(26));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(27));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(28));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(29));
    assert!(!snapshot.member_list.as_slice().bit_is_true_at_le_index(30));
    // as vec
    assert!(snapshot.member_list.bit_is_true_at_le_index(0));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(1));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(2));
    assert!(snapshot.member_list.bit_is_true_at_le_index(3));
    assert!(snapshot.member_list.bit_is_true_at_le_index(4));
    assert!(snapshot.member_list.bit_is_true_at_le_index(5));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(6));
    assert!(snapshot.member_list.bit_is_true_at_le_index(7));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(8));
    assert!(snapshot.member_list.bit_is_true_at_le_index(9));
    assert!(snapshot.member_list.bit_is_true_at_le_index(10));
    assert!(snapshot.member_list.bit_is_true_at_le_index(11));
    assert!(snapshot.member_list.bit_is_true_at_le_index(12));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(13));
    assert!(snapshot.member_list.bit_is_true_at_le_index(14));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(15));
    assert!(snapshot.member_list.bit_is_true_at_le_index(16));
    assert!(snapshot.member_list.bit_is_true_at_le_index(17));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(18));
    assert!(snapshot.member_list.bit_is_true_at_le_index(19));
    assert!(snapshot.member_list.bit_is_true_at_le_index(20));
    assert!(snapshot.member_list.bit_is_true_at_le_index(21));
    assert!(snapshot.member_list.bit_is_true_at_le_index(22));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(23));
    assert!(snapshot.member_list.bit_is_true_at_le_index(24));
    assert!(snapshot.member_list.bit_is_true_at_le_index(25));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(26));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(27));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(28));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(29));
    assert!(!snapshot.member_list.bit_is_true_at_le_index(30));
    assert_eq!(common::LLMQSnapshotSkipMode::NoSkipping, snapshot.skip_list_mode);
    assert_eq!(0, snapshot.skip_list.len());
}

#[test]
pub fn test_quorum_snapshot2() {
    let bytes1 = Vec::from_hex("01000000fd2a02ffffffffffffffffffffffffffffffffffffffffffff010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000bc0000000003000000020000000400000005000000060000000700000008000000090000000b0000000e0000002000000023000000280000002c0000002f000000340000003a0000003b0000004200000044000000490000004a0000004e000000570000005c0000005f0000006000000064000000660000006700000068000000690000006b0000006f0000007000000072000000750000007b0000007d0000007e000000810000008300000084000000850000008b0000008d000000920000009c0000009d000000a0000000a3000000a4000000a7000000a9000000aa000000ac000000ffffffff000000000500000007000000080000000b0000000f00000020000000230000002500000028000000290000002f00000031000000340000003a0000003b0000004300000044000000460000004a0000004b0000005300000060000000620000006700000068000000690000006b0000006f00000072000000750000007b0000007d000000800000008100000092000000960000009c0000009d000000a3000000a7000000ac000000ad000000ffffffff0000000002000000050000000d0000000f000000140000001b00000023000000240000002500000028000000290000002a0000002c0000002e00000031000000370000003a0000004200000043000000460000004b0000005c0000005f00000060000000610000006200000064000000650000006700000068000000690000006f00000075000000790000007b0000007d0000008b0000008f0000009200000097000000980000009c000000a0000000a3000000a5000000ac000000fdffffff000000000200000005000000080000000e000000110000001400000015000000160000001a0000001b000000280000002a0000002c000000330000003500000037000000390000003c0000003d0000003e000000410000004200000044000000490000004c0000004d0000004e000000580000005c00000065000000660000006f000000740000007600000077000000790000007b000000").unwrap();
    let bytes2 = Vec::from_hex("01000000fd2a02ffffffe6fffffbffffffff7fffeffff7fffffff7bfff03000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090090000000300000006000000090000000e000000100000001a000000220000002a0000002c00000032000000330000003700000038000000400000004300000044000000490000004d00000051000000590000005a0000005c0000005e000000620000006300000064000000650000006a0000006d0000006f00000074000000760000007c000000810000008300000086000000880000008f0000009100000098000000a3000000a5000000a800000000000000020000000500000006000000090000000d0000000e00000011000000240000002a0000002c000000300000003b000000400000004100000043000000450000004600000047000000490000004d000000520000005b0000005e00000061000000670000006a0000006b0000006d00000073000000750000007c0000007d000000800000008400000086000000880000008c000000980000009a000000a1000000a5000000a8000000010000000400000008000000090000000c0000001300000018000000200000002400000026000000290000002d000000300000003a00000041000000420000004300000046000000520000005400000056000000590000005b00000066000000680000006a0000007100000077000000870000008d0000009000000094000000950000009e000000a1000000a7000000a8000000080000000a0000000c0000000d0000000f000000120000001b0000001d000000200000002100000023000000280000002b0000002e00000032000000380000003a0000003f000000490000004b000000").unwrap();
    let snapshot1 = bytes1.as_slice().read_with::<LLMQSnapshot>(&mut 0, byte::LE).unwrap();
    let snapshot2 = bytes2.as_slice().read_with::<LLMQSnapshot>(&mut 0, byte::LE).unwrap();
    let bits1 = vec![true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,true,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,];
    let bits2 = vec![true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, false, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, false, true, true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, ];

    for i in 0..snapshot1.member_list.len() {
        assert_eq!(snapshot1.member_is_true_at_index(i as u32), bits1[i]);
        assert_eq!(snapshot1.member_list.bit_is_true_at_le_index(i as u32), bits1[i]);

    }

    for i in 0..snapshot2.member_list.len() {
        assert_eq!(snapshot2.member_is_true_at_index(i as u32), bits2[i]);
        assert_eq!(snapshot2.member_list.bit_is_true_at_le_index(i as u32), bits2[i]);
    }
}
