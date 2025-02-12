use std::fmt::{Display, Formatter};
use crate::llmq::validation_error::LLMQValidationError;
use crate::llmq::validation_skip_status::LLMQEntryValidationSkipStatus;

#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash, Debug)]
#[ferment_macro::export]
pub enum LLMQEntryValidationStatus {
    Unknown,
    Verified,
    Skipped(LLMQEntryValidationSkipStatus),
    Invalid(LLMQValidationError),
}
impl Display for LLMQEntryValidationStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            LLMQEntryValidationStatus::Unknown => "Unknown".to_string(),
            LLMQEntryValidationStatus::Verified => "Verified".to_string(),
            LLMQEntryValidationStatus::Invalid(error) => format!("Invalid({error})"),
            LLMQEntryValidationStatus::Skipped(reason) => format!("Skipped({reason})"),
        }.as_str())
    }
}
impl LLMQEntryValidationStatus  {
    pub fn is_verified(&self) -> bool {
        *self == LLMQEntryValidationStatus::Verified
    }
    pub fn is_not_verified(&self) -> bool {
        *self != LLMQEntryValidationStatus::Verified
    }

}


