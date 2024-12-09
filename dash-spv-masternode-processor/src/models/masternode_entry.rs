use byte::{BytesExt, TryRead};
use std::collections::BTreeMap;
use hashes::hex::ToHex;
use hashes::{sha256, sha256d, Hash};
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
use dash_spv_crypto::consensus::Encodable;
use dash_spv_crypto::crypto::byte_util::{UInt160, UInt256, Zeroable};
use dash_spv_crypto::keys::{ECDSAKey, OperatorPublicKey};
use dash_spv_crypto::network::{ChainType, CORE_PROTO_19_2};
use dash_spv_crypto::util::address;
use dash_spv_crypto::util::data_ops::short_hex_string_from;
use crate::common::{block::Block, masternode_type::MasternodeType, socket_address::SocketAddress};

// (block height, list diff version (2: BLSBasic), protocol_version)
#[derive(Clone, Copy)]
pub struct MasternodeReadContext(pub u32, pub u16, pub u32);

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
#[ferment_macro::export]
pub struct MasternodeEntry {
    pub provider_registration_transaction_hash: [u8; 32],
    pub confirmed_hash: [u8; 32],
    pub confirmed_hash_hashed_with_provider_registration_transaction_hash: Option<[u8; 32]>,
    pub socket_address: SocketAddress,
    pub operator_public_key: OperatorPublicKey,
    pub previous_operator_public_keys: BTreeMap<Block, OperatorPublicKey>,
    pub previous_entry_hashes: BTreeMap<Block, [u8; 32]>,
    pub previous_validity: BTreeMap<Block, bool>,
    pub known_confirmed_at_height: Option<u32>,
    pub update_height: u32,
    pub key_id_voting: [u8; 20],
    pub is_valid: bool,
    pub mn_type: MasternodeType,
    pub platform_http_port: u16,
    pub platform_node_id: [u8; 20],
    pub entry_hash: [u8; 32],
}

#[cfg(feature = "generate-dashj-tests")]
impl Serialize for MasternodeEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut state = serializer.serialize_struct("MasternodeEntry", 10)?;
        state.serialize_field("provider_registration_transaction_hash", &self.provider_registration_transaction_hash)?;
        state.serialize_field("confirmed_hash", &self.confirmed_hash)?;
        state.serialize_field("ip_address", &self.socket_address.ip_address)?;
        state.serialize_field("port", &self.socket_address.port)?;
        state.serialize_field("operator_public_key", &self.operator_public_key.data.to_hex())?;
        state.serialize_field("key_id_voting", &self.key_id_voting)?;
        state.serialize_field("is_valid", &self.is_valid)?;
        state.serialize_field("mn_type", &self.mn_type)?;
        state.serialize_field("platform_http_port", &self.platform_http_port)?;
        state.serialize_field("platform_node_id", &self.platform_node_id)?;
        state.end()

    }
}

// Define a wrapper struct for the BTreeMap.
pub struct CustomDebugBTreeMap<K, V>(pub BTreeMap<K, V>);
impl<K: std::fmt::Debug, V: std::fmt::Debug> std::fmt::Debug for CustomDebugBTreeMap<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Customize the debug representation here.
        write!(f, "BTreeMap::from([")?;
        for (key, value) in &self.0 {
            write!(f, "({:?}, {:?}), ", key, value)?;
        }
        write!(f, "])")
    }
}

impl std::fmt::Debug for MasternodeEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prev_e = CustomDebugBTreeMap(self.previous_entry_hashes.clone());
        let prev_v = CustomDebugBTreeMap(self.previous_validity.clone());
        let prev_o = CustomDebugBTreeMap(self.previous_operator_public_keys.clone());
        f.debug_struct("MasternodeEntry")
            .field("provider_registration_transaction_hash", &self.provider_registration_transaction_hash)
            .field("confirmed_hash", &self.confirmed_hash)
            .field("confirmed_hash_hashed_with_provider_registration_transaction_hash", &self.confirmed_hash_hashed_with_provider_registration_transaction_hash)
            .field("socket_address", &self.socket_address)
            .field("operator_public_key", &self.operator_public_key.data)
            .field("version", &self.operator_public_key.version)
            .field("previous_operator_public_keys", &prev_o)
            .field("previous_entry_hashes", &prev_e)
            .field("previous_validity", &prev_v)
            .field("known_confirmed_at_height", &self.known_confirmed_at_height)
            .field("update_height", &self.update_height)
            .field("key_id_voting", &self.key_id_voting)
            .field("is_valid", &self.is_valid)
            .field("mn_type", &self.mn_type)
            .field("platform_http_port", &self.platform_http_port)
            .field("platform_node_id", &self.platform_node_id)
            .field("entry_hash", &self.entry_hash)
            .finish()
    }
}
// impl consensus::Decodable for MasternodeEntry {
//     #[inline]
//     fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
//         let version = u16::consensus_decode(&mut d)?;
//         let provider_registration_transaction_hash = UInt256::consensus_decode(&mut d)?;
//         let confirmed_hash = UInt256::consensus_decode(&mut d)?;
//         let socket_address = crate::common::SocketAddress::consensus_decode(&mut d)?;
//         let mut operator_public_key = crate::models::OperatorPublicKey::consensus_decode(&mut d)?;
//         operator_public_key.version = version;
//         let key_id_voting = UInt160::consensus_decode(&mut d)?;
//         // TODO: check this logic
//         let is_valid = u8::consensus_decode(&mut d).unwrap_or(0);
//         // let index = u32::consensus_decode(&mut d)?;
//         // let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
//         // let sequence = u32::consensus_decode(&mut d)?;
//         // Ok(Self { input_hash, index, signature, sequence, script: None })
//     }
// }


impl<'a> TryRead<'a, MasternodeReadContext> for MasternodeEntry {
    fn try_read(bytes: &'a [u8], context: MasternodeReadContext) -> byte::Result<(Self, usize)> {
        let MasternodeReadContext (block_height, diff_version, protocol_version) = context;
        let offset = &mut 0;
        let version = if protocol_version >= CORE_PROTO_19_2 {
            bytes.read_with::<u16>(offset, byte::LE)?
        } else {
            1 // legacy
        };
        let provider_registration_transaction_hash =
            bytes.read_with::<UInt256>(offset, byte::LE)?.0;
        let confirmed_hash = bytes.read_with::<UInt256>(offset, byte::LE)?.0;
        let socket_address = bytes.read_with::<SocketAddress>(offset, ())?;
        let operator_public_key = bytes.read_with::<OperatorPublicKey>(offset, version)?;
        let key_id_voting = bytes.read_with::<UInt160>(offset, byte::LE)?.0;
        let is_valid = bytes.read_with::<u8>(offset, byte::LE)
            .unwrap_or(0);
         let mn_type = if version >= 2 {
            bytes.read_with::<MasternodeType>(offset, byte::LE)?
        } else {
            MasternodeType::Regular
        };
        let (platform_http_port, platform_node_id) = if mn_type == MasternodeType::HighPerformance {
            (bytes.read_with::<u16>(offset, byte::BE)?,
             bytes.read_with::<UInt160>(offset, byte::LE)?.0)
        } else {
            (0u16, [0u8; 20])
        };
        let mut entry = Self::new(
            version,
            provider_registration_transaction_hash,
            confirmed_hash,
            socket_address,
            key_id_voting,
            operator_public_key,
            is_valid,
            mn_type,
            platform_http_port,
            platform_node_id,
            block_height,
            protocol_version
        );
        if !entry.confirmed_hash.is_zero() && block_height != u32::MAX {
            entry.known_confirmed_at_height = Some(block_height);
        }
        Ok((entry, *offset))
    }
}

impl MasternodeEntry {
    pub fn new(
        version: u16,
        provider_registration_transaction_hash: [u8; 32],
        confirmed_hash: [u8; 32],
        socket_address: SocketAddress,
        key_id_voting: [u8; 20],
        operator_public_key: OperatorPublicKey,
        is_valid: u8,
        mn_type: MasternodeType,
        platform_http_port: u16,
        platform_node_id: [u8; 20],
        update_height: u32,
        protocol_version: u32,
    ) -> Self {
        let entry_hash = calculate_entry_hash(
            version,
            provider_registration_transaction_hash,
            confirmed_hash,
            socket_address,
            operator_public_key,
            key_id_voting,
            is_valid,
            mn_type,
            platform_http_port,
            platform_node_id,
            protocol_version,
        );
        Self {
            provider_registration_transaction_hash,
            confirmed_hash,
            confirmed_hash_hashed_with_provider_registration_transaction_hash: Some(
                Self::hash_confirmed_hash(confirmed_hash, provider_registration_transaction_hash),
            ),
            socket_address,
            operator_public_key,
            previous_operator_public_keys: Default::default(),
            previous_entry_hashes: Default::default(),
            previous_validity: Default::default(),
            known_confirmed_at_height: None,
            update_height,
            key_id_voting,
            is_valid: is_valid != 0,
            mn_type,
            platform_http_port,
            platform_node_id,
            entry_hash,
        }
    }
    
    pub fn update_confirmed_hash(&mut self, hash: [u8; 32]) {
        self.confirmed_hash = hash;
        if !self.provider_registration_transaction_hash.is_zero() {
            self.update_confirmed_hash_hashed_with_pro_reg_tx_hash();
        }
    }
    pub fn confirm_at_height_if_need(&mut self, block_height: u32) {
        if !self.confirmed_hash.is_zero() &&
            self.known_confirmed_at_height.is_some() &&
            self.known_confirmed_at_height.unwrap() > block_height {
            self.known_confirmed_at_height = Some(block_height);
        }
    }

    pub fn update_confirmed_hash_hashed_with_pro_reg_tx_hash(&mut self) {
        let hash = Self::hash_confirmed_hash(self.confirmed_hash, self.provider_registration_transaction_hash);
        self.confirmed_hash_hashed_with_provider_registration_transaction_hash = Some(hash)
    }


    /*pub fn payload_data(&self) -> UInt256 {
        Self::calculate_entry_hash(
            self.provider_registration_transaction_hash,
            self.confirmed_hash,
            self.socket_address,
            self.operator_public_key,
            self.key_id_voting,
            u8::from(self.is_valid),
            self.mn_type,
            self.platform_http_port,
            self.platform_node_id,
        )
    }*/




    pub fn score(&self, modifier: [u8; 32], block_height: u32) -> Option<[u8; 32]> {
        if !self.is_valid_at(block_height) ||
            self.confirmed_hash.is_zero() ||
            self.confirmed_hash_at(block_height).is_none() {
            return None;
        }
        let mut buffer: Vec<u8> = Vec::new();
        if let Some(hash) = self.confirmed_hash_hashed_with_pro_reg_tx_hash_at(block_height) {
            hash.enc(&mut buffer);
        }
        modifier.enc(&mut buffer);
        let score = sha256::Hash::hash(&buffer).into_inner();
        (!score.is_zero() && !score.is_empty()).then_some(score)
    }



    pub fn update_with_previous_entry(&mut self, entry: &mut MasternodeEntry, block_height: u32, block_hash: [u8; 32]) {
        let block = crate::common::Block::new(block_height, block_hash);
        self.previous_validity = entry
            .previous_validity
            .clone()
            .into_iter()
            .filter(|(block, _)| block.height < self.update_height)
            .collect();
        if entry.is_valid_at(self.update_height) != self.is_valid {
            self.previous_validity.insert(block, entry.is_valid);
        }
        self.previous_operator_public_keys = entry
            .previous_operator_public_keys
            .clone()
            .into_iter()
            .filter(|(block, _)| block.height < self.update_height)
            .collect();
        if entry.operator_public_key_at(self.update_height) != self.operator_public_key {
            self.previous_operator_public_keys.insert(block, entry.operator_public_key);
        }
        let old_prev_mn_entry_hashes = entry
            .previous_entry_hashes
            .clone()
            .into_iter()
            .filter(|(block, _)| block.height < self.update_height)
            .collect();
        self.previous_entry_hashes = old_prev_mn_entry_hashes;
        if entry.entry_hash_at(self.update_height) != self.entry_hash {
            self.previous_entry_hashes.insert(block, entry.entry_hash);
        }
    }
}

#[ferment_macro::export]
impl MasternodeEntry {
    pub fn entry_hash_at(&self, block_height: u32) -> [u8; 32] {
        if self.previous_entry_hashes.is_empty() || block_height == u32::MAX {
            return self.entry_hash;
        }
        let mut min_distance = u32::MAX;
        let mut used_hash = self.entry_hash;
        for (&crate::common::Block { height, .. }, &hash) in &self.previous_entry_hashes {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
                min_distance = distance;
                info!("SME Hash for proTxHash {:?} : Using {} instead of {} for list at block height {block_height}", hash.to_hex(), used_hash.to_hex(), self.provider_registration_transaction_hash.to_hex());
                used_hash = hash;
            }
        }
        used_hash
    }
    pub fn operator_public_key_at(&self, block_height: u32) -> OperatorPublicKey {
        if self.previous_operator_public_keys.is_empty() {
            return self.operator_public_key;
        }
        let mut min_distance = u32::MAX;
        let mut used_previous_operator_public_key_at_block_hash = self.operator_public_key;
        for (&Block { height, .. }, &key) in &self.previous_operator_public_keys {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
                min_distance = distance;
                info!("SME operator public key for proTxHash {:?} : Using {:?} instead of {:?} for list at block height {block_height}", key, used_previous_operator_public_key_at_block_hash, self.provider_registration_transaction_hash);
                used_previous_operator_public_key_at_block_hash = key;
            }
        }
        used_previous_operator_public_key_at_block_hash
    }
    pub fn hash_confirmed_hash(confirmed_hash: [u8; 32], provider_registration_transaction_hash: [u8; 32]) -> [u8; 32] {
        sha256::Hash::hash(&[provider_registration_transaction_hash, confirmed_hash].concat()).into_inner()
    }

    pub fn is_valid_at(&self, block_height: u32) -> bool {
        if self.previous_validity.is_empty() || block_height == u32::MAX {
            return self.is_valid;
        }
        let mut min_distance = u32::MAX;
        let mut is_valid = self.is_valid;
        for (&Block { height, .. }, &validity) in &self.previous_validity {
            if height <= block_height {
                continue;
            }
            let distance = height - block_height;
            if distance < min_distance {
                min_distance = distance;
                is_valid = validity;
            }
        }
        is_valid
    }
    pub fn unique_id(&self) -> String {
        short_hex_string_from(&self.provider_registration_transaction_hash)
    }
    pub fn confirmed_hash_hashed_with_pro_reg_tx_hash_at(
        &self,
        block_height: u32,
    ) -> Option<[u8; 32]> {
        if self.known_confirmed_at_height.is_none() || self.known_confirmed_at_height? <= block_height {
            self.confirmed_hash_hashed_with_provider_registration_transaction_hash
        } else {
            Some(Self::hash_confirmed_hash(
                [0u8; 32],
                self.provider_registration_transaction_hash,
            ))
        }
    }

    pub fn host(&self) -> String {
        format!("{}", self.socket_address)
    }
    pub fn confirmed_hash_at(&self, block_height: u32) -> Option<[u8; 32]> {
        self.known_confirmed_at_height
            .and_then(|h| (h <= block_height)
                .then_some(self.confirmed_hash))
    }

    pub fn address_is_equal_to(&self, addr: [u8; 16]) -> bool {
        addr.eq(&self.socket_address.ip_address)
    }

    pub fn confirmed_hash_is_equal_to(&self, confirmed_hash: [u8; 32]) -> bool {
        confirmed_hash.eq(&self.confirmed_hash)
    }

    pub fn key_id_is_equal_to(&self, key_id: [u8; 20]) -> bool {
        key_id.eq(&self.key_id_voting)
    }
    pub fn key_id_matches_with_secret_key(&self, secret_key: &str, chain_type: ChainType) -> bool {
        if let Ok(key) = ECDSAKey::key_with_private_key(secret_key, chain_type) {
            key.hash160().eq(&self.key_id_voting)
        } else {
            false
        }
    }
    pub fn operator_pub_key_is_equal_to(&self, operator_public_key_id: [u8; 48]) -> bool {
        operator_public_key_id.eq(&self.operator_public_key.data)
    }
    pub fn platform_node_id_is_equal_to(&self, platform_node_id: [u8; 20]) -> bool {
        platform_node_id.eq(&self.platform_node_id)
    }
    pub fn type_is_equal_to(&self, mn_type: u16) -> bool {
        MasternodeType::from(mn_type).eq(&self.mn_type)
    }
    pub fn type_uint(&self) -> u16 {
        self.mn_type.into()
    }

    pub fn operator_public_key_address(&self, chain_type: ChainType) -> String {
        address::address::with_public_key_data(&self.operator_public_key.data, chain_type)
    }
    pub fn voting_address(&self, chain_type: ChainType) -> String {
        let script_map = chain_type.script_map();
        address::address::from_hash160_for_script_map(&self.key_id_voting, &script_map)
    }
    pub fn evo_node_address(&self, chain_type: ChainType) -> String {
        let script_map = chain_type.script_map();
        address::address::from_hash160_for_script_map(&self.platform_node_id, &script_map)
    }

}

pub fn calculate_entry_hash(
    version: u16,
    provider_registration_transaction_hash: [u8; 32],
    confirmed_hash: [u8; 32],
    socket_address: SocketAddress,
    operator_public_key: OperatorPublicKey,
    key_id_voting: [u8; 20],
    is_valid: u8,
    mn_type: MasternodeType,
    platform_http_port: u16,
    platform_node_id: [u8; 20],
    protocol_version: u32,
) -> [u8; 32] {
    let mut writer = Vec::<u8>::new();
    provider_registration_transaction_hash.enc(&mut writer);
    confirmed_hash.enc(&mut writer);
    socket_address.enc(&mut writer);
    operator_public_key.enc(&mut writer);
    key_id_voting.enc(&mut writer);
    is_valid.enc(&mut writer);
    if version >= 2 {
        u16::from(mn_type).enc(&mut writer);
        if mn_type == MasternodeType::HighPerformance {
            platform_http_port.swap_bytes().enc(&mut writer);
            platform_node_id.enc(&mut writer);
        }
    }
    sha256d::Hash::hash(&writer).into_inner()
}

#[ferment_macro::export]
pub fn new(
    version: u16,
    provider_registration_transaction_hash: [u8; 32],
    confirmed_hash: [u8; 32],
    ip_address: [u8; 16],
    port: u16,
    key_id_voting: [u8; 20],
    operator_public_key_data: [u8; 48],
    operator_public_key_version: u16,
    is_valid: u8,
    mn_type: u16,
    platform_http_port: u16,
    platform_node_id: [u8; 20],
    update_height: u32,
    protocol_version: u32
) -> MasternodeEntry {
    MasternodeEntry::new(
        version,
        provider_registration_transaction_hash,
        confirmed_hash,
        SocketAddress { ip_address, port },
        key_id_voting,
        OperatorPublicKey { data: operator_public_key_data, version: operator_public_key_version },
        is_valid,
        MasternodeType::from(mn_type),
        platform_http_port,
        platform_node_id,
        update_height,
        protocol_version
    )
}
#[ferment_macro::export]
pub fn from_entity(
    version: u16,
    provider_registration_transaction_hash: [u8; 32],
    confirmed_hash: [u8; 32],
    ip_address: [u8; 16],
    port: u16,
    key_id_voting: [u8; 20],
    operator_public_key_data: [u8; 48],
    operator_public_key_version: u16,
    is_valid: bool,
    mn_type: u16,
    platform_http_port: u16,
    platform_node_id: [u8; 20],
    update_height: u32,
    confirmed_hash_hashed_with_provider_registration_transaction_hash: [u8; 32],
    known_confirmed_at_height: u32,
    entry_hash: [u8; 32],
    previous_entry_hashes: Vec<[u8; 68]>,
    previous_operator_public_keys: Vec<[u8; 86]>,
    previous_validity: Vec<[u8; 37]>,
) -> MasternodeEntry {
    let previous_entry_hashes = previous_entry_hashes
        .into_iter()
        .map(|bytes| {
            let hash: [u8; 32] = bytes[..32].try_into().unwrap();
            let height = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
            let entry_hash: [u8; 32] = bytes[36..].try_into().unwrap();
            (Block { height, hash }, entry_hash)
        })
        .collect();
    let previous_operator_public_keys = previous_operator_public_keys.into_iter().map(|bytes| {
        let hash: [u8; 32] = bytes[..32].try_into().unwrap();
        let height = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
        let data: [u8; 48] = bytes[36..84].try_into().unwrap();
        let version = u16::from_le_bytes([bytes[84], bytes[85]]);
        (Block { height, hash }, OperatorPublicKey { data, version } )
    }).collect();
    let previous_validity = previous_validity
        .into_iter()
        .map(|bytes| {
            let hash: [u8; 32] = bytes[..32].try_into().unwrap();
            let height = u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]);
            let b: bool = bytes[36] != 0;
            (Block { height, hash }, b)
        })
        .collect();

    MasternodeEntry {
        provider_registration_transaction_hash,
        confirmed_hash,
        confirmed_hash_hashed_with_provider_registration_transaction_hash: Some(confirmed_hash_hashed_with_provider_registration_transaction_hash),
        socket_address: SocketAddress { ip_address, port },
        operator_public_key: OperatorPublicKey { data: operator_public_key_data, version: operator_public_key_version },
        previous_operator_public_keys,
        previous_entry_hashes,
        previous_validity,
        known_confirmed_at_height: Some(known_confirmed_at_height),
        update_height,
        key_id_voting,
        is_valid,
        mn_type: MasternodeType::from(mn_type),
        platform_http_port,
        platform_node_id,
        entry_hash,
    }
}