pub mod processor;
pub mod keys_cache;
pub mod core_provider;

use std::net::SocketAddr;
use dashcore::consensus::{deserialize, serialize};
use dashcore::{ChainLock, InstantLock, blockdata::transaction::outpoint::OutPoint, hash_types::PubkeyHash};
use dashcore::bls_sig_utils::BLSPublicKey;
use dashcore::hashes::Hash;
use dashcore::sml::masternode_list::MasternodeList;
use dash_spv_crypto::network::ChainType;
use dash_spv_crypto::util::{from_hash160_for_script_map, with_public_key_data};
pub use self::core_provider::{CoreProvider, CoreProviderError};
pub use self::processor::MasternodeProcessor;



#[ferment_macro::export]
pub fn instant_lock_from_message(message: &[u8]) -> Option<InstantLock> {
    deserialize(message).ok()
}
#[ferment_macro::export]
pub fn instant_lock_to_message(lock: &InstantLock) -> Vec<u8> {
    serialize(lock)
}
#[ferment_macro::export]
pub fn chain_lock_from_message(message: &[u8]) -> Option<ChainLock> {
    deserialize(message).ok()
}
#[ferment_macro::export]
pub fn chain_lock_to_message(lock: &ChainLock) -> Vec<u8> {
    serialize(lock)
}

#[ferment_macro::export]
pub fn outpoint_from_message(message: &[u8]) -> Option<OutPoint> {
    deserialize(message).ok()
}
#[ferment_macro::export]
pub fn outpoint_to_message(lock: &OutPoint) -> Vec<u8> {
    serialize(lock)
}

#[ferment_macro::export]
pub fn operator_public_key_address(public_key: BLSPublicKey, chain_type: ChainType) -> String {
    with_public_key_data(&public_key.0, chain_type)
}
#[ferment_macro::export]
pub fn voting_address(key_id_voting: PubkeyHash, chain_type: ChainType) -> String {
    let script_map = chain_type.script_map();
    from_hash160_for_script_map(key_id_voting.as_byte_array(), &script_map)
}
#[ferment_macro::export]
pub fn evo_node_address(evo_node_id: PubkeyHash, chain_type: ChainType) -> String {
    let script_map = chain_type.script_map();
    from_hash160_for_script_map(evo_node_id.as_byte_array(), &script_map)
}

#[ferment_macro::export]
pub fn peer_addresses_with_connectivity_nonce(masternode_list: MasternodeList, nonce: u64, max_count: usize) -> Vec<([u8; 16], u16)> {
    masternode_list.peer_addresses_with_connectivity_nonce(nonce, max_count).into_iter().map(|socket_addr| match socket_addr {
            SocketAddr::V4(v4) => {
                let mut writer = [0u8; 16];
                writer[12..].copy_from_slice(&v4.ip().octets());
                (writer, v4.port())
            },
            SocketAddr::V6(v6) => (v6.ip().octets(), v6.port())
        }
    ).collect()
}

#[ferment_macro::export]
pub fn socket_addr_port(socket_addr: SocketAddr) -> u16 {
    match socket_addr {
        SocketAddr::V4(v4) => v4.port(),
        SocketAddr::V6(v6) => v6.port()
    }
}

#[ferment_macro::export]
pub fn socket_addr_ip(socket_addr: SocketAddr) -> [u8; 16] {
    match socket_addr {
        SocketAddr::V4(v4) => {
            let mut octets = [0u8; 16];
            octets[8..12].copy_from_slice(&v4.ip().octets());
            octets
        },
        SocketAddr::V6(v6) => v6.ip().octets()
    }
}
