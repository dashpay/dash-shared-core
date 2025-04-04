use std::fmt::{Debug, Formatter};
use dashcore::secp256k1::hashes::hex::DisplayHex;

#[derive(Debug, PartialEq, Eq)]
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
            ScriptElement::Data(data, _) => write!(f, "{}", data.to_lower_hex_string())?,
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
    use crate::util::data_append::DataAppend;
    use crate::util::script::ScriptElement;

    fn check_script_elements(data: &[u8], exp_script_elements: Vec<ScriptElement>) {
        assert_eq!(
            data.to_vec().script_elements(),
            exp_script_elements.clone(),
            "Script Elements don't match");
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

}
