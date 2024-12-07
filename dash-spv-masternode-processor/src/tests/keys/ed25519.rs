use base64::{alphabet, Engine};
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use hashes::hex::{FromHex, ToHex};
use hashes::{Hash, sha256};
use dash_spv_crypto::derivation::{IIndexPath, IndexPath};
use dash_spv_crypto::crypto::{UInt160, UInt256, UInt512};
use dash_spv_crypto::keys::{IKey, key::KeyKind, DeriveKey};

fn test_derivation_path() {

}

// Test vectors taken from  https://github.com/satoshilabs/slips/blob/master/slip-0010.md
#[test]
pub fn test_key_with_private_key() {
    let seed_data = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    //--------------------------------------------------------------------------------------------------//
    // m //
    // fingerprint: 00000000
    // chain code: ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b
    // private: 171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012
    // public: 008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a
    //--------------------------------------------------------------------------------------------------//
    let i = UInt512::ed25519_seed_key(&seed_data);
    let seckey = ed25519_dalek::SecretKey::try_from(&i.0[..32]).unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seckey);
    let public_key = UInt256::from(ed25519_dalek::VerifyingKey::from(&signing_key));
    let chaincode = UInt256::from(&i.0[32..]);
    assert_eq!(signing_key.to_bytes().to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    // assert_eq!(public_key.0.to_hex(), "008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
    assert_eq!(public_key.0.to_hex(), "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
}

/// Without padding-byte 0x00 in public key data there are different result for this test vectors
///
#[test]
pub fn test_vector_1_derivation() {
    // Test Vector 1
    let seed_data = Vec::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
    let seed_key = KeyKind::ED25519.key_with_seed_data(&seed_data).unwrap();
    //--------------------------------------------------------------------------------------------------//
    // Chain m
    //--------------------------------------------------------------------------------------------------//
    println!("••••••••••••••••••••••••••••••••••••••");
    let indexes = vec![];
    let hardened = vec![];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64).0];
    let hardened = vec![true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0xddebc675u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "8c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(1u32).0];
    let hardened = vec![true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0x13dab143u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "1932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(1u32).0, UInt256::from(2u32).0];
    let hardened = vec![true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0xebe4cb29u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(1u32).0, UInt256::from(2u32).0, UInt256::from(2u32).0];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0x316ec1c6u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "8abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H/1000000000H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(1u32).0, UInt256::from(2u32).0, UInt256::from(2u32).0, UInt256::from(1000000000u64).0];
    let hardened = vec![true, true, true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0xd6322ccdu32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "3c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
}


#[test]
pub fn test_vector_2_derivation() {
    // Test Vector 1
    let seed_data = Vec::from_hex("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542").unwrap();
    let seed_key = KeyKind::ED25519.key_with_seed_data(&seed_data).unwrap();
    //--------------------------------------------------------------------------------------------------//
    // Chain m
    //--------------------------------------------------------------------------------------------------//
    println!("••••••••••••••••••••••••••••••••••••••");
    let indexes = vec![];
    let hardened = vec![];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64).0];
    let hardened = vec![true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0x31981b50u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "86fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64).0, UInt256::from(2147483647u64).0];
    let hardened = vec![true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0x1e9411b1u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "5ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(2147483647u64).0, UInt256::from(1u32).0];
    let hardened = vec![true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0xfcadf38cu32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "2e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(2147483647u64).0, UInt256::from(1u32).0, UInt256::from(2147483646u64).0];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0xaca70953u32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32).0, UInt256::from(2147483647u64).0, UInt256::from(1u32).0, UInt256::from(2147483646u64).0, UInt256::from(2u32).0];
    let hardened = vec![true, true, true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0x422c654bu32.swap_bytes(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "47150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
}


#[test]
pub fn test_platform_node_key_derivation() {
    let seed_data = Vec::from_hex("44cb0848958cb77898e464d18e3c70e2a437b343a894defa6010c5056a2b4a1caa01d04760871b578721b0a797fd1aacdfcd77f1870dddb34f1b204d5dbe07c0").unwrap();
    let seed_key = KeyKind::ED25519.key_with_seed_data(&seed_data).unwrap();

    //--------------------------------------------------------------------------------------------------//
    // Chain m
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![];
    let hardened = vec![];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "e9e82625ceba55e48938338bf9e5c65f295995a056c4245f56111d20ed4483ce", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "f7b51597adf83c1adac7548b86ce1b310d92cee606ada8ed77ebb2e897579c3f", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "bd1de92c05b3a56067887d081e03a0cf65666d8f719bb70b9932106b4e4848ec", "public key is wrong");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0];
    let hardened = vec![true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 1680968818u32, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "d6217f1090e57c89e8466a68a524a4ad200abcd4710b5e636e2251bdb9d3a178", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "4fa90d6d6fcc62320ecdd8726ac2831707a28f07650aa995d6f1e58b69e0cf3f", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "e7b90950199237c73e6fcce396a4cc1d3bf9b2095a02f463deed7f3f4e3377b6", "public key is wrong");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'/5'
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0, UInt256::from(5u32).0];
    let hardened = vec![true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 3111175390u32, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "f16eb77c77266fc40a35864cb9140076de928ffbe4d02f0e059de2012d178ab5", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "d5447a2806ad8077235d4f98f4883ac98293a819a4ed97e5b00d976a6f7abecd", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "5c02a36691329fb024b7c4f05c6601c7ca3014160c529a2596755f13a77999c0", "public key is wrong");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'/5'/3'
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0, UInt256::from(5u32).0, UInt256::from(3u32).0];
    let hardened = vec![true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 208479033u32, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "4de438f0b3a812faf3af2e898907fcdf3a5a2f70ce69e35e9c4f65bb9e273e6c", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "cfb8aa1eca1c24f9f1efc46425901fe8f285d47c480a8a8c32800954967b994e", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "6931ef2303d2e4be4d8c53e5245349f1eb054f27e4c086cef3c7b163e4251ea5", "public key is wrong");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'/5'/3'/4'
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0, UInt256::from(5u32).0, UInt256::from(3u32).0, UInt256::from(4u32).0];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 3805166404u32, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "5240adb1df0ac47b8cd8d2355c3a8f8f03783b54e28128937e5e4cc1530e71d7", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "32700c6d3124260f71ee8dda05138270ad3362768ca4d31b4297825b14947bb4", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "f2d0fa62e162350ebe9d7a74a816b3d9e6481b9f962b5370749d8168ae1bfe92", "public key is wrong");

    let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'/5'/3'/4'/0' (last index is UInt256) as SLIP-0010
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0, UInt256::from(5u32).0, UInt256::from(3u32).0, UInt256::from(4u32).0, UInt256::from(0u32).0];
    let hardened = vec![true, true, true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    let key_id = UInt160::from(&sha256::Hash::hash(&private_key.public_key_data())[..20]);
    let base64_keys = base64_engine.encode(&[&private_key.secret_key(), &private_key.public_key_data()[..]].concat());
    assert_eq!(private_key.fingerprint(), 2497558984u32, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().to_hex(), "587dc2c7de6d36e06c6de0a2989cd8cb112c1e41b543002a5ff422f3eb1e8cd6", "chain code is wrong");
    assert_eq!(private_key.secret_key().to_hex(), "7898dbaa7ab9b550e3befcd53dc276777ffc8a27124f830c04e17fcf74b9e071", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "08e2698fdcaa0af8416966ba9349b0c8dfaa80ed7f4094e032958a343e45f4b6", "public key is wrong");
    assert_eq!(key_id.0.to_hex(), "c9bbba6a3ad5e87fb11af4f10458a52d3160259c", "key id is wrong");
    assert_eq!(base64_keys, "eJjbqnq5tVDjvvzVPcJ2d3/8iicST4MMBOF/z3S54HEI4mmP3KoK+EFpZrqTSbDI36qA7X9AlOAylYo0PkX0tg==", "base64 is wrong");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/9'/5'/3'/4'/0' (last index is u32) as DASH
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(9u32).0, UInt256::from(5u32).0, UInt256::from(3u32).0, UInt256::from(4u32).0];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::<[u8; 32]>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_path(&index_path).unwrap();
    let private_child = private_key.private_derive_to_path(&IndexPath::new_hardened(vec![0], vec![true])).unwrap();
    let key_id = UInt160::from(&sha256::Hash::hash(&private_child.public_key_data())[..20]);
    let base64_keys = base64_engine.encode(&[&private_child.secret_key(), &private_child.public_key_data()[..]].concat());
    assert_eq!(private_child.fingerprint(), 2497558984u32, "fingerprint is wrong");
    assert_eq!(private_child.chaincode().to_hex(), "587dc2c7de6d36e06c6de0a2989cd8cb112c1e41b543002a5ff422f3eb1e8cd6", "chain code is wrong");
    assert_eq!(private_child.secret_key().to_hex(), "7898dbaa7ab9b550e3befcd53dc276777ffc8a27124f830c04e17fcf74b9e071", "private key is wrong");
    assert_eq!(private_child.public_key_data().to_hex(), "08e2698fdcaa0af8416966ba9349b0c8dfaa80ed7f4094e032958a343e45f4b6", "public key is wrong");
    assert_eq!(key_id.0.to_hex(), "c9bbba6a3ad5e87fb11af4f10458a52d3160259c", "key id is wrong");
    assert_eq!(base64_keys, "eJjbqnq5tVDjvvzVPcJ2d3/8iicST4MMBOF/z3S54HEI4mmP3KoK+EFpZrqTSbDI36qA7X9AlOAylYo0PkX0tg==", "base64 is wrong");
}
