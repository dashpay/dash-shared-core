#[cfg(feature = "test-helpers")]
use std::collections::BTreeMap;
#[cfg(feature = "test-helpers")]
use dash_spv_crypto::network::{ChainType, DevnetType, IHaveChainSettings};
#[cfg(feature = "test-helpers")]
use crate::block_store::{init_mainnet_store, init_testnet_store, MerkleBlock};
#[cfg(feature = "test-helpers")]
use crate::processing::CoreProviderError;

#[cfg(test)]
pub mod hashes;
#[cfg(test)]
pub mod indexes;
#[cfg(test)]
pub mod keys;
#[cfg(test)]
pub mod listdiff;
#[cfg(feature = "serde")]
pub mod serde_helper;

#[derive(Debug)]
#[cfg(feature = "test-helpers")]
pub struct FFIContext {
    pub chain: ChainType,
    pub is_dip_0024: bool,
    //pub cache: Arc<MasternodeProcessorCache>,
    // TODO:: make it initialized from json file with blocks
    pub blocks: Vec<MerkleBlock>,
    pub cl_signatures: BTreeMap<[u8; 32], [u8; 96]>,
}
#[cfg(feature = "test-helpers")]
impl Drop for FFIContext {
    fn drop(&mut self) {
        println!("FFIContext is being dropped");
    }
}
#[cfg(feature = "test-helpers")]
impl FFIContext {
    pub fn block_for_hash(&self, hash: [u8; 32]) -> Option<&MerkleBlock> {
        self.blocks.iter().find(|block| hash.eq(&block.hash.0))
    }
    pub fn get_tip_height(&self) -> u32 {
        self.blocks.iter().map(MerkleBlock::height).max().unwrap_or(u32::MAX)
    }
    pub fn block_height_for_hash(&self, block_hash: [u8; 32]) -> u32 {
        self.block_for_hash(block_hash)
            .map(MerkleBlock::height)
            .unwrap_or(u32::MAX)

    }
    pub fn block_hash_for_height(&self, block_height: u32) -> Result<[u8; 32], CoreProviderError> {
        self.block_for_height(block_height)
            .map(MerkleBlock::hash)
            .ok_or(CoreProviderError::BlockHashNotFoundAt(block_height))
    }

    pub fn block_for_height(&self, height: u32) -> Option<&MerkleBlock> {
        self.blocks.iter().find(|block| block.height == height)
    }

    pub fn cl_signature_by_block_hash(&self, block_hash: &[u8; 32]) -> Option<&[u8; 96]> {
        self.cl_signatures.get(block_hash)
    }
    pub fn genesis_as_ptr(&self) -> *const u8 {
        self.chain.genesis_hash().as_ptr()
    }

    pub fn chain_default(chain: ChainType, is_dip_0024: bool, blocks: Vec<MerkleBlock>) -> Self {
        Self { chain, is_dip_0024, blocks, cl_signatures: BTreeMap::new() }
    }
    pub fn create_default_context(chain: ChainType, is_dip_0024: bool) -> Self {
        let blocks = match chain {
            ChainType::MainNet => init_mainnet_store(),
            ChainType::TestNet => init_testnet_store(),
            _ => vec![],
        };
        Self { chain, is_dip_0024, blocks, cl_signatures: BTreeMap::new()  }
    }
    pub fn create_default_context_and_cache(chain: ChainType, is_dip_0024: bool) -> Self {
        let blocks = match chain {
            ChainType::MainNet => init_mainnet_store(),
            ChainType::TestNet => init_testnet_store(),
            _ => vec![],
        };
        Self::chain_default(chain, is_dip_0024, blocks)
    }
    pub fn devnet_default(devnet: DevnetType, is_dip_0024: bool, blocks: Vec<MerkleBlock>) -> Self {
        Self::chain_default(ChainType::DevNet(devnet), is_dip_0024, blocks)
    }
}