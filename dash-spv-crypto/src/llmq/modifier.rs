use hashes::sha256d;
use dashcore::consensus::Encodable;
use dashcore::consensus::encode::VarInt;
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
                VarInt(u64::from(llmq_type)).consensus_encode(&mut writer).unwrap();
                block_hash.consensus_encode(&mut writer).unwrap();
            },
            LLMQModifierType::CoreV20(llmq_type, block_height, cl_signature) => {
                VarInt(u64::from(llmq_type)).consensus_encode(&mut writer).unwrap();
                block_height.consensus_encode(&mut writer).unwrap();
                cl_signature.consensus_encode(&mut writer).unwrap();
            }
        }
        sha256d::Hash::hash(writer.as_ref()).to_byte_array()
    }
}
