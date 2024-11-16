use dash_spv_crypto::crypto::UInt256;

#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct LLMQIndexedHash {
    pub index: u32,
    pub hash: UInt256,
}

impl LLMQIndexedHash {
    pub fn new(hash: UInt256, index: u32) -> Self {
        LLMQIndexedHash { index, hash }
    }
}

impl From<(UInt256, usize)> for LLMQIndexedHash {
    fn from(value: (UInt256, usize)) -> Self {
        Self::new(value.0, value.1 as u32)
    }
}
impl From<(UInt256, u32)> for LLMQIndexedHash {
    fn from(value: (UInt256, u32)) -> Self {
        Self::new(value.0, value.1)
    }
}
