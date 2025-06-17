use std::ffi::c_void;
use std::sync::Arc;
use dash_spv_crypto::network::ChainType;
use dash_spv_storage::entity::Entity;
use crate::TransactionModel;

pub trait ChainRef {
    fn chain_ref(&self) -> &ChainController;
}

pub trait Notification {
    fn name(&self) -> String;
}
// pub

#[derive(Clone)]
pub struct ChainController {
    pub chain_type: ChainType,
    pub get_chain_by_chain_type: Arc<dyn Fn(ChainType) -> *const c_void>,
    pub get_wallet: Arc<dyn Fn(*const c_void, /*unique_id*/&str) -> *const c_void>,
    pub get_transaction_by_entity: Arc<dyn Fn(*const c_void, Entity) -> Option<TransactionModel>>,
    pub get_block_height_by_hash: Arc<dyn Fn(*const c_void, [u8; 32]) -> u32>,
    pub get_block_hash_by_height: Arc<dyn Fn(*const c_void, u32) -> Option<[u8; 32]>>,
}



impl ChainController {
    pub fn new<
        GetChainByChainType: Fn(ChainType) -> *const c_void + Send + Sync + 'static,
        GetWallet: Fn(*const c_void, &str) -> *const c_void + Send + Sync + 'static,
        GetTransactionByEntity: Fn(*const c_void, Entity) -> Option<TransactionModel> + Send + Sync + 'static,
        GetBlockHeightByHash: Fn(*const c_void, [u8; 32]) -> u32 + Send + Sync + 'static,
        GetBlockHashByHeight: Fn(*const c_void, u32) -> Option<[u8; 32]> + Send + Sync + 'static,
    >(
        chain_type: ChainType,
        get_chain_by_chain_type: GetChainByChainType,
        get_wallet: GetWallet,
        get_transaction_by_entity: GetTransactionByEntity,
        get_block_height_by_hash: GetBlockHeightByHash,
        get_block_hash_by_height: GetBlockHashByHeight,
    ) -> ChainController {
        Self {
            chain_type,
            get_chain_by_chain_type: Arc::new(get_chain_by_chain_type),
            get_wallet: Arc::new(get_wallet),
            get_transaction_by_entity: Arc::new(get_transaction_by_entity),
            get_block_height_by_hash: Arc::new(get_block_height_by_hash),
            get_block_hash_by_height: Arc::new(get_block_hash_by_height),
        }
    }

    pub fn get_chain_by_chain_type(&self) -> *const c_void {
        (self.get_chain_by_chain_type)(self.chain_type.clone())
    }
    pub fn get_wallet(&self, unique_id: &str) -> *const c_void {
        let chain = self.get_chain_by_chain_type();
        (self.get_wallet)(chain, unique_id)
    }

    pub fn get_transaction_by_entity(&self, entity: Entity) -> Option<TransactionModel> {
        let chain = self.get_chain_by_chain_type();
        (self.get_transaction_by_entity)(chain, entity)
    }
    pub fn get_block_height_by_hash(&self, hash: [u8; 32]) -> u32 {
        let chain = self.get_chain_by_chain_type();
        (self.get_block_height_by_hash)(chain, hash)
    }
    pub fn get_block_hash_by_height(&self, height: u32) -> Option<[u8; 32]> {
        let chain = self.get_chain_by_chain_type();
        (self.get_block_hash_by_height)(chain, height)
    }

}