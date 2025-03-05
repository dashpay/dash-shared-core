use std::fmt::{Display, Formatter};
use dashcore::secp256k1::hashes::hex::DisplayHex;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
#[ferment_macro::export]
pub enum LLMQEntryValidationSkipStatus {
    MissedList([u8; 32]),
    UnknownBlock([u8; 32]),
    OtherContext(String),
    Outdated(u32, u32)
}

impl Display for LLMQEntryValidationSkipStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQEntryValidationSkipStatus::MissedList(block_hash) => format!("MissedList({})", block_hash.to_lower_hex_string()),
            LLMQEntryValidationSkipStatus::UnknownBlock(block_hash) => format!("UnknownBlock({})", block_hash.to_lower_hex_string()),
            LLMQEntryValidationSkipStatus::OtherContext(message) => format!("OtherContext({message})"),
            LLMQEntryValidationSkipStatus::Outdated(block_height, tip_height) => format!("Outdated({block_height}/{tip_height})"),
        }.as_str())
    }
}

