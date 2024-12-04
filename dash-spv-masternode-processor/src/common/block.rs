use std::fmt::Display;
use hashes::hex::ToHex;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[ferment_macro::export]
pub struct Block {
    pub height: u32,
    pub hash: [u8; 32],
}
impl std::fmt::Debug for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Block")
            .field("height", &self.height)
            .field("hash", &self.hash)
            .finish()
    }
}
impl Display for Block {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Block(height: {}, hash: {})", self.height, self.hash.to_hex())
    }
}

impl Block {
    pub fn new(height: u32, hash: [u8; 32]) -> Self {
        Self { height, hash }
    }
}

