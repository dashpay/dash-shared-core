use hashes::{sha256d, Hash};
use crate::consensus::Encodable;
use crate::consensus::encode::VarInt;
use crate::network::LLMQType;

pub enum LLMQModifierType {
    PreCoreV20(LLMQType, [u8; 32]),
    CoreV20(LLMQType, u32, [u8; 96]),
}

impl LLMQModifierType {
    pub fn build_llmq_hash(&self) -> [u8; 32] {
        let mut writer = vec![];
        match self {
            LLMQModifierType::PreCoreV20(llmq_type, block_hash) => {
                VarInt(llmq_type.clone() as u64).enc(&mut writer);
                block_hash.enc(&mut writer);
            },
            LLMQModifierType::CoreV20(llmq_type, block_height, cl_signature) => {
                VarInt(llmq_type.clone() as u64).enc(&mut writer);
                block_height.enc(&mut writer);
                cl_signature.enc(&mut writer);
            }
        }
        sha256d::Hash::hash(writer.as_ref()).into_inner()
    }
}
