use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::crypto::{UInt256, UInt768};
use crate::network::LLMQType;

pub enum LLMQModifierType {
    PreCoreV20(LLMQType, UInt256),
    CoreV20(LLMQType, u32, UInt768),
}

impl LLMQModifierType {
    pub fn build_llmq_hash(&self) -> UInt256 {
        let mut writer = vec![];
        match *self {
            LLMQModifierType::PreCoreV20(llmq_type, block_hash) => {
                VarInt(llmq_type as u64).enc(&mut writer);
                block_hash.enc(&mut writer);
            },
            LLMQModifierType::CoreV20(llmq_type, block_height, cl_signature) => {
                VarInt(llmq_type as u64).enc(&mut writer);
                block_height.enc(&mut writer);
                cl_signature.enc(&mut writer);
            }
        }
        UInt256::sha256d(writer)
    }
}
