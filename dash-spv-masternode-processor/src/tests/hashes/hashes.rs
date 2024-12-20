use base64::{alphabet, Engine};
use base64::engine::{GeneralPurpose, GeneralPurposeConfig};
use hashes::hex::{FromHex, ToHex};
use crate::crypto::{UInt160, UInt256, UInt512};
use crate::util::base58;

#[test]
fn test_base64_hash_size() {
    let hash = UInt256::sha256d(Vec::from_hex("aaaa").unwrap());
    let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
    let base64_data = base64_engine.encode(hash.0);
    assert_eq!(base64_data.len(), 44, "The size of the base64 should be 44");
}
#[test]
fn test_blake3() {
    let md = blake3::hash("".as_bytes());
    assert_eq!(md.to_hex().as_str(), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "blake 3 err");
}

/*#[test]
fn test_blake512() {
    let input = UInt512::from_hex("020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300").unwrap();
    let md = blake3::hash(&input.0);
    assert_eq!(md.to_hex().as_str(), "728309A76516B83D4E326DB3C6782722129C2835A25DE336DFFC16A0C10E4EBA654D65A86C7CC606B80BEFCC665CDD9B2D966D6BDCD2179F226F36925CC1AB8F", "blake 512 err");
}*/

#[test]
fn test_x11() {
    let x11 = "020000002cc0081be5039a54b686d24d5d8747ee9770d9973ec1ace02e5c0500000000008d7139724b11c52995db4370284c998b9114154b120ad3486f1a360a1d4253d310d40e55b8f70a1be8e32300";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("f29c0f286fd8071669286c6987eb941181134ff5f3978bf89f34070000000000", output.to_hex(), "x11 error");

    let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2000000000";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("2990cb88c53c588b58188f6868972ec37e955903940ab7604da44c3291204cce", output.to_hex(), "x11 error");

    let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2001000000";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("412a340f4a1442b42f703523f2c5c041d5eed7dfad6bd7eda16b8d55e575f7df", output.to_hex(), "x11 error");

    let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2002000000";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("000739d9da507b3acb949f21fe10ad424abbad5b4c46789285b05fe36df5c5b0", output.to_hex(), "x11 error");

    let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2003000000";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("90ec0543cd91297e7ad3d3141a404fb55f787b3058aca2b45ab0fc20d06409c6", output.to_hex(), "x11 error");

    let x11 = "040000002e3df23eec5cd6a86edd509539028e2c3a3dc05315eb28f2baa43218ca080000b3a56d65316ffdb006163240a4380e94a4c2d8c0f0b3b2c1ddc486fae15ed065ba968054ffff7f2004000000";
    let input = Vec::from_hex(x11).unwrap();
    let output = rs_x11_hash::get_x11_hash(input);
    assert_eq!("eee8ff78056e3b0cd35cd8e267fa871270a183a5d05c764d8c2047b7c3cca014", output.to_hex(), "x11 error");
}

#[test]
fn test_base58() {
    let s = base58::from("Ƀ#&$@*^(*#!^");
    assert!(s.is_err(), "base58::from");
    let s = base58::from("");
    assert_eq!(s.unwrap().to_hex(), "", "base58::from");
    let s = base58::from("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    assert_eq!(base58::encode_slice(&s.unwrap()), "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "base58");
    let s = base58::from("1111111111111111111111111111111111111111111111111111111111111111111");
    assert_eq!(base58::encode_slice(&s.unwrap()), "1111111111111111111111111111111111111111111111111111111111111111111", "base58");
    let s = base58::from("111111111111111111111111111111111111111111111111111111111111111111z");
    assert_eq!(base58::encode_slice(&s.unwrap()), "111111111111111111111111111111111111111111111111111111111111111111z", "base58");
    let s = base58::from("z");
    assert_eq!(base58::encode_slice(&s.unwrap()), "z", "base58");
    let s = base58::from_check("");
    assert_eq!(s, Err(base58::Error::TooShort(0)), "base58");
    let s = base58::check_encode_slice(&Vec::from_hex("000000000000000000000000000000000000000000").unwrap());
    assert_eq!(base58::from_check(s.as_str()).unwrap(), Vec::from_hex("000000000000000000000000000000000000000000").unwrap(), "base58");
    let s = base58::check_encode_slice(&Vec::from_hex("000000000000000000000000000000000000000001").unwrap());
    assert_eq!(base58::from_check(s.as_str()).unwrap(), Vec::from_hex("000000000000000000000000000000000000000001").unwrap(), "base58");
    let s = base58::check_encode_slice(&Vec::from_hex("05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap());
    assert_eq!(base58::from_check(s.as_str()).unwrap(), Vec::from_hex("05FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap(), "base58");
}

#[test]
fn test_sha1() {
    assert_eq!(
        UInt160::from_hex("6fc2e25172cb15193cb1c6d48f607d42c1d2a215").unwrap(),
        UInt160::sha1("Free online SHA1 Calculator, type text here...".as_bytes()),
        "sha1 error");
    assert_eq!(
        UInt160::from_hex("085194658a9235b2951a83d1b826b987e9385aa3").unwrap(),
        UInt160::sha1("this is some text to test the sha1 implementation with more than 64bytes of data since it's internal digest buffer is 64bytes in size".as_bytes()),
        "sha1 error");
    assert_eq!(
        UInt160::from_hex("245be30091fd392fe191f4bfcec22dcb30a03ae6").unwrap(),
        UInt160::sha1("123456789012345678901234567890123456789012345678901234567890".as_bytes()),
        "sha1 error");
    assert_eq!(
        UInt160::from_hex("c71490fc24aa3d19e11282da77032dd9cdb33103").unwrap(),
        UInt160::sha1("1234567890123456789012345678901234567890123456789012345678901234".as_bytes()),
        "sha1 error");
    assert_eq!(
        UInt160::from_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709").unwrap(),
        UInt160::sha1("".as_bytes()),
        "sha1 error");
    assert_eq!(
        UInt160::from_hex("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8").unwrap(),
        UInt160::sha1("a".as_bytes()),
        "sha1 error");
}

#[test]
fn test_sha256() {
    assert_eq!(
        UInt256::from_hex("43fd9deb93f6e14d41826604514e3d7873a549ac87aebebf3d1c10ad6eb057d0").unwrap(),
        UInt256::sha256("Free online SHA256 Calculator, type text here...".as_bytes()),
        "sha256 error");
    assert_eq!(
        UInt256::from_hex("40fd0933df2e7747f19f7d39cd30e1cb89810a7e470638a5f623669f3de9edd4").unwrap(),
        UInt256::sha256("this is some text to test the sha256 implementation with more than 64bytes of data since it's internal digest buffer is 64bytes in size".as_bytes()),
        "sha256 error");
    assert_eq!(
        UInt256::from_hex("decc538c077786966ac863b5532c4027b8587ff40f6e3103379af62b44eae44d").unwrap(),
        UInt256::sha256("123456789012345678901234567890123456789012345678901234567890".as_bytes()),
        "sha256 error");
    assert_eq!(
        UInt256::from_hex("676491965ed3ec50cb7a63ee96315480a95c54426b0b72bca8a0d4ad1285ad55").unwrap(),
        UInt256::sha256("1234567890123456789012345678901234567890123456789012345678901234".as_bytes()),
        "sha256 error");
    assert_eq!(
        UInt256::from_hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").unwrap(),
        UInt256::sha256("".as_bytes()),
        "sha256 error");
    assert_eq!(
        UInt256::from_hex("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb").unwrap(),
        UInt256::sha256("a".as_bytes()),
        "sha256 error");
}

#[test]
fn test_sha512() {
    assert_eq!(
        UInt512::from_hex("04f1154135eecbe42e9adc8e1d532f9c607a8447b786377db8447d11a5b2232cdd419b8639224f787a51d110f72591f96451a1bb511c4a829ed0a2ec891321f3").unwrap(),
        UInt512::sha512("Free online SHA512 Calculator, type text here...".as_bytes()),
        "sha512 error");
    assert_eq!(
        UInt512::from_hex("9bd2dc7b05fbbe9934cb3289b6e06b8ca9fd7a55e6de5db7e1e4eeddc6629b575307367cd0183a4461d7eb2dfc6a27e41e8b70f6598ebcc7710911d4fb16a390").unwrap(),
        UInt512::sha512("this is some text to test the sha512 implementation with more than 128bytes of data since it's internal digest buffer is 128bytes in size".as_bytes()),
        "sha512 error");
    assert_eq!(
        UInt512::from_hex("0d9a7df5b6a6ad20da519effda888a7344b6c0c7adcc8e2d504b4af27aaaacd4e7111c713f71769539629463cb58c86136c521b0414a3c0edf7dc6349c6edaf3").unwrap(),
        UInt512::sha512("123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".as_bytes()),
        "sha512 error");
    assert_eq!(
        UInt512::from_hex("222b2f64c285e66996769b5a03ef863cfd3b63ddb0727788291695e8fb84572e4bfe5a80674a41fd72eeb48592c9c79f44ae992c76ed1b0d55a670a83fc99ec6").unwrap(),
        UInt512::sha512("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678".as_bytes()),
        "sha512 error");
    assert_eq!(
        UInt512::from_hex("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e").unwrap(),
        UInt512::sha512("".as_bytes()),
        "sha512 error");
    assert_eq!(
        UInt512::from_hex("1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75").unwrap(),
        UInt512::sha512("a".as_bytes()),
        "sha512 error");
}

#[test]
fn test_ripemd160() {
    assert_eq!(
        UInt160::from_hex("9501a56fb829132b8748f0ccc491f0ecbc7f945b").unwrap(),
        UInt160::ripemd160("Free online RIPEMD160 Calculator, type text here...".as_bytes()),
        "ripemd160 error");
    assert_eq!(
        UInt160::from_hex("4402eff42157106a5d92e4d946185856fbc50e09").unwrap(),
        UInt160::ripemd160("this is some text to test the ripemd160 implementation with more than 64bytes of data since it's internal digest buffer is 64bytes in size".as_bytes()),
        "ripemd160 error");
    assert_eq!(
        UInt160::from_hex("00263b999714e756fa5d02814b842a2634dd31ac").unwrap(),
        UInt160::ripemd160("123456789012345678901234567890123456789012345678901234567890".as_bytes()),
        "ripemd160 error");
    assert_eq!(
        UInt160::from_hex("fa8c1a78eb763bb97d5ea14ce9303d1ce2f33454").unwrap(),
        UInt160::ripemd160("1234567890123456789012345678901234567890123456789012345678901234".as_bytes()),
        "ripemd160 error");
    assert_eq!(
        UInt160::from_hex("9c1185a5c5e9fc54612808977ee8f548b2258d31").unwrap(),
        UInt160::ripemd160("".as_bytes()),
        "ripemd160 error");
    assert_eq!(
        UInt160::from_hex("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe").unwrap(),
        UInt160::ripemd160("a".as_bytes()),
        "ripemd160 error");
}
