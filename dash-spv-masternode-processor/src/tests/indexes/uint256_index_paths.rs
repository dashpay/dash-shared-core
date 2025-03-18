use std::cmp::Ordering;
use dash_spv_crypto::crypto::byte_util::Random;
use dash_spv_crypto::derivation::{IIndexPath, UInt256IndexPath};

fn generate_random_indexes_for_length(length: usize) -> Vec<[u8; 32]> {
    (0..length).into_iter().map(|i| <[u8; 32]>::random()).collect()
}

fn perform_tests_for_indexes(indexes: Vec<[u8; 32]>) {
    let length = indexes.len();
    let mut index_path = UInt256IndexPath::index_path_with_indexes(indexes.clone());
    // Basic
    for (i, in_index) in indexes.into_iter().enumerate() {
        assert_eq!(in_index, index_path.index_at_position(i), "Failed for length {}", length);
    }

    // todo: impl Serialization test

    // Methods
    let index = <[u8; 32]>::random();
    let mut new_index_path = index_path.index_path_by_adding_index(index);
    let returned_index = new_index_path.index_at_position(length);
    assert_eq!(returned_index, index, "Failed for length {}", length);
    // todo: impl Hashing test
    // assert_eq!(returned_index.ha, index, "Failed for length {}", length);
    //XCTAssert(newIndexPath.hash == indexPath.hash, @"Failed for length %ld", length);

    if length > 2 {
        let slice_length = length - 2;
        // new_index_path = new_index_path.index_path_by_removing_last_index();
        new_index_path = UInt256IndexPath::index_path_with_indexes(index_path.indexes()[1..slice_length+1].to_vec());
        assert_eq!(new_index_path.length(), slice_length)
    }

}

#[test]
pub fn test_empty_index_path() {
    let mut index_path = UInt256IndexPath::new(vec![]);
    assert_eq!(index_path.length(), 0, "Non-zero index path length");
    // let mut hasher = DefaultHasher::new();
    // index_path.hash(&mut hasher);
    // assert_eq!(hasher.finish(), 0, "Non-zero index path hash");
    index_path = index_path.index_path_by_removing_last_index();
    assert_eq!(index_path.length(), 0, "Non-zero index path length");
    let index = index_path.index_at_position(1);
    assert_eq!(index_path.index_at_position(1), [!0u8; 32], "Non-existed index should be ::MAX");
    index_path = index_path.index_path_by_adding_index(from_u64_4_to_u8_32([1,2,3,4]));
    assert_eq!(index_path.length(), 1, "Non-existed index should be ::MAX");
}

#[test]
pub fn test_many_elements() {
    let max_indexes_count = 1000;
    for length in 1..max_indexes_count {
        perform_tests_for_indexes(generate_random_indexes_for_length(length));
    }
}

#[test]
pub fn test_compare_elements() {
    let first_path = UInt256IndexPath::index_path_with_indexes(vec![from_u64_4_to_u8_32([1,2,3,4]), from_u64_4_to_u8_32([2,3,4,5])]);
    let second_path = UInt256IndexPath::index_path_with_indexes(vec![from_u64_4_to_u8_32([5,6,7,8]), from_u64_4_to_u8_32([6,7,8,9])]);
    assert_eq!(first_path.cmp(&second_path), Ordering::Less);
    assert_eq!(second_path.cmp(&first_path), Ordering::Greater);
}

fn from_u64_4_to_u8_32(value: [u64; 4]) -> [u8; 32] {
    let mut r = [0u8; 32];
    r[..8].copy_from_slice(&value[0].to_le_bytes());
    r[8..16].copy_from_slice(&value[1].to_le_bytes());
    r[16..24].copy_from_slice(&value[2].to_le_bytes());
    r[24..].copy_from_slice(&value[3].to_le_bytes());
    r
}
