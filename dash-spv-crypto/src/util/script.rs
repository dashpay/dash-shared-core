use std::fmt::{Debug, Formatter};
use hashes::hex::ToHex;

#[derive(Debug)]
pub enum ScriptType {
    PayToPubkey,
    PayToPubkeyHash,
    PayToScriptHash,
    Unknown,
}

impl From<ScriptType> for &str {
    fn from(value: ScriptType) -> Self {
        match value {
            ScriptType::PayToPubkey => "pay-to-pubkey",
            ScriptType::PayToPubkeyHash => "pay-to-pubkey-hash",
            ScriptType::PayToScriptHash => "pay-to-script-hash",
            ScriptType::Unknown => "unknown",
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScriptElement<'a> {
    Number(u8),
    Data(&'a [u8], u8)
}

impl<'a> Debug for ScriptElement<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ScriptElement::Number(code) => write!(f, "{:02x}", code)?,
            ScriptElement::Data(data, _) => write!(f, "{}", data.to_hex())?,
        }
        Ok(())
    }
}

pub fn op_len(data: &[u8]) -> u8 {
    match data.len() {
        // < OP_PUSHDATA1
        0..=0x4d => data.len() as u8,
        // <= u8::MAX,
        0x4e..=0xff => 0x4c,
        // <= u16::MAX
        0x0100..=0xffff => 0x4d,
        //
        _ => 0x4e
    }
}

#[cfg(test)]
mod tests {
    use hashes::hex::{FromHex, ToHex};

    use crate::util::address::address;
    use crate::util::{base58, ScriptMap};
    use crate::util::data_append::DataAppend;
    use crate::util::script::ScriptElement;

    // fn check_script_elements(data: &[u8], expected_script_elements: &[u8], exp_script_type: ScriptType) {
    //     let vec_data = data.to_vec();
    //     let script = Script::from(vec_data);
    //     assert_eq!(
    //         script.elements,
    //         exp_script_elements.to_vec(),
    //         format!("Script Elements from {:?} don't match: {:?} != {:?}", vec_data, script.elements, exp_script_elements));
    //     assert_eq!(script.r#type, exp_script_type, format!("Script type don't match {:?} != {:?}", script.r#type, exp_script_type));
    // }
    //
    // #[test]
    // fn test_script_elements() {
    //     // ScriptPubKey: None
    //     check_script_elements(
    //         &[0x6a], // 1 byte
    //         &[106u8],
    //         ScriptType::Unknown);
    //
    //     // ScriptPubKey: b"\x8c\x96\x73\x0b\xae\xea\x3f\xe1\x9b\x24\xac\x2e\x24\xc3\xc2\xd7\x79\xc6\xb2\x76\x93" // 21 bytes
    //     check_script_elements(
    //         b"\x76\xa9\x14\x96\x73\x0b\xae\xea\x3f\xe1\x9b\x24\xac\x2e\x24\xc3\xc2\xd7\x79\xc6\xb2\x76\x93\x88\xac", // 25 bytes
    //         &[[118u8], &[169u8], b"\x09\xce\xdf\xc4\xdb\x61\xd5\xd9\xbf\xae\x7d\xc8\x3d\x16\xc5\x95\xe9\x61\x17\x1e", &[136u8], &[172u8]].concat(),
    //         ScriptType::PayToPubkeyHash);
    //
    // }

    fn check_script_elements(data: &[u8], exp_script_elements: Vec<ScriptElement>) {
        assert_eq!(
            data.to_vec().script_elements(),
            exp_script_elements.clone(),
            "Script Elements don't match");
    }

    fn check_address_with_script_pubkey(data: &[u8], script_map: &ScriptMap, address: Option<String>) {
        let elem = data.to_vec().script_elements();
        let addr = address::with_script_pub_key(&data.to_vec(), script_map);
        assert_eq!(addr, address, "Address with script pubkey don't match")
    }

    fn check_address_with_script_signature(data: &[u8], script_map: &ScriptMap, address: Option<String>) {
        let elem = data.to_vec().script_elements();
        let addr = address::with_script_sig(&data.to_vec(), script_map);
        println!("check_address_with_script_signature: {:?} => {:?}", data.to_hex(), address);
        assert_eq!(addr, address, "Address with script signature don't match")
    }

    #[test]
    fn test_script_elements() {
        // ScriptPubKey: None
        check_script_elements(b"\x6a", vec![ScriptElement::Number(106)]);
        check_script_elements(
            b"\x76\xa9\x14\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60\x88\xac",
            vec![
                ScriptElement::Number(118),
                ScriptElement::Number(169),
                ScriptElement::Data(b"\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60", 20),
                ScriptElement::Number(136),
                ScriptElement::Number(172)
            ]);
    }

    #[test]
    fn test_address_with_script_pubkey() {
        check_address_with_script_pubkey(
            b"\x6a",
            &ScriptMap::TESTNET,
            None
        );
        check_address_with_script_pubkey(
            b"\x76\xa9\x14\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60\x88\xac",
            &ScriptMap::TESTNET,
            Some(base58::check_encode_slice(b"\x8c\x35\x1d\xdf\x96\xc5\xf0\x51\x25\x84\xe1\xbe\x4e\x77\xc7\x3b\x96\x20\x3a\x6b\x60"))
        );
        check_address_with_script_pubkey(
            Vec::from_hex("76a914351ddf96c5f0512584e1be4e77c73b96203a6b6088ac").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            Some(String::from("yRAJT1XYopJPLriAoS4rHA87GKd8gGW9rN"))
        );
        check_address_with_script_pubkey(
            Vec::from_hex("6a1414ec6c36e6c39a9181f3a261a08a5171425ac5e2").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            None
        );
        check_address_with_script_pubkey(
            Vec::from_hex("76a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288ac").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            Some(String::from("yNE5ayfLHEpunjKYJoD9oDNNfCcpeZtDf2"))
        );
        check_address_with_script_pubkey(
            Vec::from_hex("76a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            Some(String::from("yMWfjiYVs5X4pYpxrWG4tkrSA3mi5zUW8f"))
        );
    }

    #[test]
    fn test_address_with_script_signature() {
        check_address_with_script_signature(
            b"\x01\x6a\x01\x01",
            &ScriptMap::TESTNET,
            Some("8xPfejPddAMauCGJZCSGjq33pQWi4uQtpR".to_string()));
        check_address_with_script_signature(
            Vec::from_hex("4730440220437f15af30180be323ca1a1e0c47de2a597abba2a57d4f76e2584ce7d3e8d40802202705342f334991c9eaa2757ea63c5bb305abf14a66a1ce727ef2689a92bcee55012103a65caff6ca4c0415a3ac182dfc2a6d3a4dceb98e8b831e71501df38aa156f2c1").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            Some("yNPbcFfabtNmmxKdGwhHomdYfVs6gikbPf".to_string()));
        check_address_with_script_signature(
            Vec::from_hex("47304402204972e37e8b7ae4aeb30388b79dfb6067fe6a2d3fd751e1031b924b857bfe483c02200c58de282b10dc536a161b34a606890779d552ba618738018ad1f21f669912540121038d18456ebe83c1650166a1d5145c9a9456b35f9258338b54d98257b968b765da").unwrap().as_slice(),
            &ScriptMap::TESTNET,
            Some("ya2XwWQUzfC7kvLUVsdPteaeCxfAS4yLEC".to_string()));

        check_address_with_script_signature(
            Vec::from_hex("a0a0a0a0a0a0a0a0a0a0").unwrap().as_slice(),
            &ScriptMap::MAINNET,
            None);
    }

}
