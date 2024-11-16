use dash_spv_crypto::network::LLMQType;
use dash_spv_crypto::crypto::UInt256;

#[derive(Debug, Copy, Clone)]
#[ferment_macro::export]
pub struct LLMQTypedHash {
    pub llmq_type: LLMQType,
    pub hash: UInt256,
}
