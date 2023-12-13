use crate::crypto::byte_util::UInt256;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[ferment_macro::export]
pub struct Block {
    pub height: u32,
    pub hash: UInt256,
}
impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("height", &self.height)
            .field("hash", &self.hash)
            .finish()
    }
}

impl Block {
    pub fn new(height: u32, hash: UInt256) -> Self {
        Self { height, hash }
    }
}

