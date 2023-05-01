use hashes::hex::{FromHex, ToHex};
use crate::chain::derivation::{IIndexPath, IndexPath};
use crate::crypto::{UInt256, UInt512};
use crate::keys::{IKey, KeyKind};

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
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64)];
    let hardened = vec![true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("69e8577b").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "b307fed094e548bdd725dd946073136451fd4259f161fbdcad7892fe4b849267", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "263a25182eb17ddc3ca84467d480bf3afbd383619e45188a54624da340717df6", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "408beec8c8eda1302f554edee0e4e0d28eff1e852390b2aeedbf107d8d59679e", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(1u32)];
    let hardened = vec![true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("f00d1e1c").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "362b1cab1aa6aadd331bd0aab73986fe7654ea65aa26adfddcd4e16c41a81bdd", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "bcf19f49f025ef1872fbef76c503674c40f9b535b7f9d2ad2c1300942968d0ea", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "154f104f509ddc6f165f49188b2c3b0b2fda14c8632b1ce007f1ee1faebdf2d5", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32)];
    let hardened = vec![true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("fec60588").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "44da8805d0451eb3ae91e52cf90a71cbb6b44bcc09ab765ea45a81ce8532b0cc", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "b24a1b962511fa147383fd36a8c87c2d8af1e2718b555e389000789dfdfd4651", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "e0058ed08bfe349453e2d40b7cbb7606d7fa3dac7c3f6f756182a42a8fa4b5cd", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32), UInt256::from(2u32)];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("676458de").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "172b6a88ab3fca00615af6aabb355ea9fff8a34b3c4c6d8d17b683fb412cbb0f", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "b6c7575b7327391e8310da69a59c82c16e5938e77ec86465dc75df9bbe788b94", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "6ef147b3fc3765e2be1f89d4b03f70f7323921b6ddf44a1752483269d81819ed", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/1H/2H/2H/1000000000H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(1u32), UInt256::from(2u32), UInt256::from(2u32), UInt256::from(1000000000u64)];
    let hardened = vec![true, true, true, true, true];
    let index_path = IndexPath::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("6d205270").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "c845c62fc11620a9baccea1ce6ff657892d866516037e17453b27abedde3e38f", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "fe5a062acc906c23648c892979e4ec0d8266e33ef3fdbf765cc4de19c886ace4", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "9532aea0cb26170539ab1ae7f101f79cf27725a00b10074ebc6add33872e0bd8", "public key is wrong");
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
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint(), 0, "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "8fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64)];
    let hardened = vec![true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("c6e5512a").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "2a1ba3d06a3accda18bc7ed6bff47b78d80be5c1641c8c07def2cf8cb229a078", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "5c0915bcb6c38a51292023db99d0ce7db07facb898e80d0321eba5afd53f69c0", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "2d76d670e2c1873a012973c840f74343a0ad10149644a275c6139ee053d681a1", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u64), UInt256::from(2147483647u64)];
    let hardened = vec![true, true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("40b443bd").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "bf3dc38ccc53caae2b2bb622ffc71bab13e4e290542c0edf8f7116ffc80605a3", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "6c2e51273dbd5ea4c6c99a6df48f077dc5c6bda46cec67bf4ea3c869d4c1e036", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "9ed180e7a58a74471d9989cac237686d9a1cb4245e605f7e5fc2259abf7c9940", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32)];
    let hardened = vec![true, true, true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("80a89165").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "5e33c9206c7ab6d5953957daced9f9fb04b50373b1a3a9c66f83b437073494c4", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "615b7ec4f3930bca8da3f47ec3dae32d4a613df6ba1f353d4fc8d17026d6a067", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "ded83db2ad3bb741bec15f93a1d24030e1ca249e765d66b49dca1aba270fc1ac", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32), UInt256::from(2147483646u64)];
    let hardened = vec![true, true, true, true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("bbde61c1").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "b1ce6c5a5f654ba6fc6b53e3f8a7ace78bd95a3a2af4dd5f5b31ffc620eb376d", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "6d74b1b04dac77b54cfd2b80135cceac80b9fde83f8a2ca7d5ee0282b18fe1e9", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "cee65c0d7feb16f71d923c2cc4ed0a87c2d9fd0bb603721a03ae50e256c6a8ad", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");

    //--------------------------------------------------------------------------------------------------//
    // Chain m/0H/2147483647H/1H/2147483646H/2H
    //--------------------------------------------------------------------------------------------------//
    let indexes = vec![UInt256::from(0u32), UInt256::from(2147483647u64), UInt256::from(1u32), UInt256::from(2147483646u64), UInt256::from(2u32)];
    let hardened = vec![true, true, true, true, true];
    let index_path = IndexPath::<UInt256>::new_hardened(indexes, hardened);
    let private_key = seed_key.private_derive_to_256bit_derivation_path(&index_path).unwrap();
    assert_eq!(private_key.fingerprint().to_hex(), Vec::from_hex("685ca0ae").unwrap().to_hex(), "fingerprint is wrong");
    assert_eq!(private_key.chaincode().0.to_hex(), "7ebbf16212d10e17f0f42d3265c836bfd2d563e433345755b0f1b8421def8423", "chain code is wrong");
    assert_eq!(private_key.secret_key().0.to_hex(), "43a4d36c18de9949e4e43883083d5dbebf99cfbc658448609131505d932a2ad7", "private key is wrong");
    assert_eq!(private_key.public_key_data().to_hex(), "2573212fb7f146012f89793ea96d9917a69898789656a3ec62db56198feed609", "public key is wrong");
    println!("••••••••••••••••••••••••••••••••••••••");
}
