use std::fmt::Display;
use dashcore::BlockHash;
use hashes::hex::ToHex;

#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[ferment_macro::export]
pub struct Block {
    pub height: u32,
    pub hash: [u8; 32],
}
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
#[ferment_macro::export]
pub struct MBlock {
    pub height: u32,
    pub hash: [u8; 32],
    pub merkle_root: [u8; 32],
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
impl std::fmt::Debug for MBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MBlock")
            .field("height", &self.height)
            .field("block_hash", &self.hash)
            .field("merkle_root", &self.merkle_root)
            .finish()
    }
}
impl Display for MBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MBlock(height: {}, hash: {}, merkle_root: {})", self.height, self.hash.to_hex(), self.merkle_root.to_hex())
    }
}

impl Block {
    pub fn new(height: u32, hash: [u8; 32]) -> Self {
        Self { height, hash }
    }
}
impl MBlock {
    pub fn new(height: u32, hash: [u8; 32], merkle_root: [u8; 32]) -> Self {
        Self { height, hash, merkle_root }
    }
}

