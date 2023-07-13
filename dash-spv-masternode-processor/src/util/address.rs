pub mod address {
    use hashes::{Hash, hash160, sha256d};
    use hashes::hex::{FromHex, ToHex};
    use crate::chain::params::{BITCOIN_PUBKEY_ADDRESS, BITCOIN_SCRIPT_ADDRESS, ScriptMap};
    use crate::consensus::Encodable;
    use crate::crypto::byte_util::clone_into_array;
    use crate::crypto::UInt160;
    use crate::util::base58;
    use crate::util::data_append::DataAppend;
    use crate::util::script::ScriptElement;
    use crate::util::sec_vec::SecVec;

    pub fn from_hash160_for_script_map(hash: &UInt160, map: &ScriptMap) -> String {
        let mut writer: Vec<u8> = Vec::new();
        map.pubkey.enc(&mut writer);
        hash.enc(&mut writer);
        let val = u32::from_le_bytes(clone_into_array(&sha256d::Hash::hash(&writer).into_inner()[..4]));
        val.enc(&mut writer);
        base58::encode_slice(&writer)
    }

    pub fn with_public_key_data(data: &[u8], map: &ScriptMap) -> String {
        let mut writer = SecVec::with_capacity(21);
        map.pubkey.enc(&mut writer);
        UInt160::hash160(data).enc(&mut writer);
        base58::check_encode_slice(&writer)
    }


    // NOTE: It's important here to be permissive with scriptSig (spends) and strict with scriptPubKey (receives). If we
    // miss a receive transaction, only that transaction's funds are missed, however if we accept a receive transaction that
    // we are unable to correctly sign later, then the entire wallet balance after that point would become stuck with the
    // current coin selection code
    pub fn with_script_pub_key(script: &Vec<u8>, map: &ScriptMap) -> Option<String> {
        match script.script_elements()[..] {
            // pay-to-pubkey-hash scriptPubKey
            [ScriptElement::Number(0x76/*OP_DUP*/), ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x88/*OP_EQUALVERIFY*/), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
                Some([&[map.pubkey], data].concat()),
            // pay-to-script-hash scriptPubKey
            [ScriptElement::Number(0xa9/*OP_HASH160*/), ScriptElement::Data(data, len @ b'\x14'), ScriptElement::Number(0x87/*OP_EQUAL*/)] =>
                Some([&[map.script], data].concat()),
            // pay-to-pubkey scriptPubKey
            [ScriptElement::Data(data, len @ 33u8 | len @ 65u8), ScriptElement::Number(0xac/*OP_CHECKSIG*/)] =>
                Some([&[map.pubkey] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
            // unknown script type
            _ => None
        }.map(|data| base58::check_encode_slice(&data))
    }

    pub fn with_script_sig(script: &Vec<u8>, map: &ScriptMap) -> Option<String> {
        match script.script_elements()[..] {
            // pay-to-pubkey-hash scriptSig
            [.., ScriptElement::Data(.., 0..=0x4e), ScriptElement::Data(data, len @ 33 | len @ 65)] =>
                Some([&[map.pubkey] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
            // pay-to-script-hash scriptSig
            [.., ScriptElement::Data(.., 0..=0x4e), ScriptElement::Data(data, len @ 0..=0x4e)] =>
                Some([&[map.script] as &[u8], &hash160::Hash::hash(data).into_inner()].concat()),
            // pay-to-pubkey scriptSig
            // TODO: implement Peter Wullie's pubKey recovery from signature
            [.., ScriptElement::Data(.., 0..=0x4e)] => None,
            // unknown script type
            _ => None
        }.map(|data| base58::check_encode_slice(&data))

    }

    pub fn is_valid_dash_address_for_script_map(address: &str, map: &ScriptMap) -> bool {
        if address.len() > 35 {
            return false;
        }
        match base58::from_check(address) {
            Ok(d) if d.len() == 21 => d[0] == map.pubkey || d[0] == map.script,
            _ => false
        }
    }

    pub fn is_valid_dash_devnet_address(address: &str) -> bool {
        is_valid_dash_address_for_script_map(address, &ScriptMap::TESTNET)
    }

    pub fn shapeshift_outbound_force_script(script: Vec<u8>) -> Option<String> {
        match &script[..] {
            // [b'\x6a', len, b'\xb1', other @ ..] => Some(base58::check_encode_slice(&[[BITCOIN_SCRIPT_ADDRESS], other[..len][..]].concat())),
            [b'\x6a', len, b'\xb1', other @ ..] => Some(base58::check_encode_slice(&[&[BITCOIN_SCRIPT_ADDRESS], &other[..*len as usize]].concat())),
            _ => None
        }
    }

    pub fn shapeshift_outbound_for_script(script: Vec<u8>) -> Option<String> {
        match &script[..] {
            // OP_RETURN, length, OP_SHAPESHIFT
            // &[b'\x6a', len, b'\xb1', other @ ..] =>
            [b'\x6a', len, b'\xb1', other @ ..] =>
                Some(base58::check_encode_slice(&[&[BITCOIN_PUBKEY_ADDRESS], &other[..*len as usize]].concat())),
            // OP_RETURN, length, OP_SHAPESHIFT_SCRIPT
            [b'\x6a', len, b'\xb3', other @ ..] =>
                Some(base58::check_encode_slice(&[&[BITCOIN_SCRIPT_ADDRESS], &other[..*len as usize]].concat())),
            _ => None
        }
    }

    pub fn is_valid_dash_private_key(address: &str, map: &ScriptMap) -> bool {
        // let data = address.as_str();
        base58::from_check(address).map_or(false, |d| {
            if d.len() == 33 || d.len() == 34 {
                // wallet import format: https://en.bitcoin.it/wiki/Wallet_import_format
                d[0] == map.privkey
            } else {
                // hex encoded key
                let hex_key = address.as_bytes().to_hex();
                if let Ok(data) = Vec::from_hex(hex_key.as_str()) {
                    data.len() == 32
                } else {
                    false
                }
            }
        })
    }

}
