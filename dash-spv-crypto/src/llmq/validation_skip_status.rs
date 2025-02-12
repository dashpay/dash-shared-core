use std::fmt::{Display, Formatter};
use hashes::hex::ToHex;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
#[ferment_macro::export]
pub enum LLMQEntryValidationSkipStatus {
    MissedList([u8; 32]),
    UnknownBlock([u8; 32]),
    OtherContext(String),
}

impl Display for LLMQEntryValidationSkipStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQEntryValidationSkipStatus::MissedList(block_hash) => format!("MissedList({})", block_hash.to_hex()),
            LLMQEntryValidationSkipStatus::UnknownBlock(block_hash) => format!("UnknownBlock({})", block_hash.to_hex()),
            LLMQEntryValidationSkipStatus::OtherContext(message) => format!("OtherContext({message})"),
        }.as_str())
    }
}

