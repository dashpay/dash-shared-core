use dashcore::secp256k1::hashes::hex::DisplayHex;
use dashcore::sml::masternode_list_entry::qualified_masternode_list_entry::QualifiedMasternodeListEntry;
use dash_spv_crypto::network::ChainType;

#[ferment_macro::opaque]
pub trait CoreProvider: std::fmt::Debug + Send + Sync {
    fn chain_type(&self) -> ChainType;
    fn lookup_block_hash_by_height(&self, block_height: u32) -> Option<[u8; 32]>;
    fn lookup_block_height_by_hash(&self, block_hash: [u8; 32]) -> u32;
    fn update_address_usage_of_masternodes(&self, masternodes: Vec<QualifiedMasternodeListEntry>);
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[ferment_macro::export]
pub enum CoreProviderError {
    NullResult(String),
    BadBlockHash([u8; 32]),
    UnknownBlockHeightForHash([u8; 32]),
    BlockHashNotFoundAt(u32),
    NoSnapshot([u8; 32]),
    HexError(dashcore::hashes::hex::Error),
    MissedMasternodeListAt([u8; 32]),
}
impl std::fmt::Display for CoreProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            CoreProviderError::NullResult(message) =>
                format!("CoreProviderError::NullResult({message})"),
            CoreProviderError::BadBlockHash(h) =>
                format!("CoreProviderError::BadBlockHash({})", h.to_lower_hex_string()),
            CoreProviderError::UnknownBlockHeightForHash(h) =>
                format!("CoreProviderError::UnknownBlockHeightForHash({})", h.to_lower_hex_string()),
            CoreProviderError::BlockHashNotFoundAt(h) =>
                format!("CoreProviderError::BlockHashNotFound({h})"),
            CoreProviderError::HexError(err) =>
                format!("CoreProviderError::HexError({err})"),
            CoreProviderError::NoSnapshot(block_hash) =>
                format!("CoreProviderError::NoSnapshot({})", block_hash.to_lower_hex_string()),
            CoreProviderError::MissedMasternodeListAt(block_hash) =>
                format!("CoreProviderError::MissedMasternodeListAt({})", block_hash.to_lower_hex_string()),
        })
    }
}

impl std::error::Error for CoreProviderError {}


