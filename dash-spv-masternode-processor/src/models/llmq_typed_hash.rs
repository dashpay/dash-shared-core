use crate::chain::common::llmq_type::LLMQType;
use crate::crypto::byte_util::UInt256;

#[derive(Debug, Copy, Clone)]
#[ferment_macro::export]
pub struct LLMQTypedHash {
    pub llmq_type: LLMQType,
    pub hash: UInt256,
}
