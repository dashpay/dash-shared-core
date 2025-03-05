use std::fmt::{Display, Formatter};
use std::io;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use log::{info, warn};
// use secp256k1::ThirtyTwoByteHash;
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
use dashcore::consensus::{Decodable, encode::VarInt, Encodable};
use dashcore::hashes::{sha256, sha256d, Hash};
use dashcore::secp256k1::hashes::hex::DisplayHex;
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::crypto::byte_util::Reversed;
use crate::impl_bytes_decodable;
use crate::keys::BLSKey;
use crate::llmq::{Bitset, LLMQVersion};
use crate::llmq::validation_status::LLMQEntryValidationStatus;
use crate::network::LLMQType;


#[derive(Clone, Ord, PartialOrd, PartialEq, Eq, Hash)]
#[ferment_macro::export]
pub struct LLMQEntry {
    pub version: LLMQVersion,
    pub llmq_hash: [u8; 32],
    pub index: u16,
    // pub index: Option<u16>,
    pub public_key: [u8; 48],
    pub threshold_signature: [u8; 96],
    pub verification_vector_hash: [u8; 32],
    pub all_commitment_aggregated_signature: [u8; 96],
    pub llmq_type: LLMQType,
    pub signers: Bitset,
    pub valid_members: Bitset,
    pub entry_hash: [u8; 32],
    pub verified: LLMQEntryValidationStatus,
    pub saved: bool,
    pub commitment_hash: Option<[u8; 32]>,
}
impl_bytes_decodable!(LLMQEntry);

#[cfg(feature = "generate-dashj-tests")]
impl Serialize for LLMQEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut state = serializer.serialize_struct("LLMQEntry", 10 + usize::from(self.index != u16::MAX))?;
        state.serialize_field("version", &self.version)?;
        if self.index != u16::MAX {
            state.serialize_field("index", &self.index)?;
        }
        state.serialize_field("public_key", &self.public_key.to_lower_hex_string())?;
        state.serialize_field("threshold_signature", &self.threshold_signature.to_lower_hex_string())?;
        state.serialize_field("verification_vector_hash", &self.verification_vector_hash.to_lower_hex_string())?;
        state.serialize_field("all_commitment_aggregated_signature", &self.all_commitment_aggregated_signature.to_lower_hex_string())?;
        state.serialize_field("llmq_type", &self.llmq_type)?;
        state.serialize_field("signers", &self.signers.to_string())?;
        state.serialize_field("valid_members", &self.valid_members.to_string())?;
        state.end()
    }
}
impl Display for LLMQEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let q_index = if self.index == u16::MAX { "no".to_string() } else { format!("{}", self.index) };
        let desc = format!("{} v{} [{}] [{}/{}] llmq_hash: {}, pk: {}, ts: {}, vv: {}, asig: {}, signers: {}::{}, members: {}::{}, entry_hash: {}, commitment_hash: {}",
            self.llmq_type,
            self.version.index(),
            q_index,
            self.verified,
            if self.saved { "yes" } else { "no" },
            self.llmq_hash.to_lower_hex_string(),
            self.public_key.to_lower_hex_string(),
            self.threshold_signature.to_lower_hex_string(),
            self.verification_vector_hash.to_lower_hex_string(),
            self.all_commitment_aggregated_signature.to_lower_hex_string(),
            self.signers.count, self.signers.bitset.to_lower_hex_string(),
            self.valid_members.count, self.valid_members.bitset.to_lower_hex_string(),
            self.entry_hash.to_lower_hex_string(),
            self.commitment_hash.map(|h|h.to_lower_hex_string()).unwrap_or("None".to_string())
        );
        write!(f, "{}", desc)

    }
}

impl std::fmt::Debug for LLMQEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQEntry")
            .field("version", &self.version)
            .field("llmq_hash", &self.llmq_hash.to_lower_hex_string())
            .field("index", &self.index)
            .field("public_key", &self.public_key.to_lower_hex_string())
            .field("threshold_signature", &self.threshold_signature.to_lower_hex_string())
            .field("verification_vector_hash", &self.verification_vector_hash.to_lower_hex_string())
            .field("all_commitment_aggregated_signature", &self.all_commitment_aggregated_signature.to_lower_hex_string())
            .field("llmq_type", &self.llmq_type)
            .field("signers", &self.signers)
            .field("valid_members", &self.valid_members)
            .field("entry_hash", &self.entry_hash.to_lower_hex_string())
            .field("verified", &self.verified)
            .field("saved", &self.saved)
            .field("commitment_hash", &self.commitment_hash.map_or("None".to_string(), |h| h.to_lower_hex_string()))
            .finish()
    }
}

impl Encodable for LLMQEntry {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(writer)?;
        len += self.llmq_type.consensus_encode(writer)?;
        len += self.llmq_hash.consensus_encode(writer)?;
        if self.version.use_rotated_quorums() {
            len += self.index.consensus_encode(writer)?;
        }
        len += self.signers.consensus_encode(writer)?;
        len += self.valid_members.consensus_encode(writer)?;
        len += self.public_key.consensus_encode(writer)?;
        len += self.verification_vector_hash.consensus_encode(writer)?;
        len += self.threshold_signature.consensus_encode(writer)?;
        len += self.all_commitment_aggregated_signature.consensus_encode(writer)?;
        Ok(len)
    }
}

impl Decodable for LLMQEntry {
    #[inline]
    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, dashcore::consensus::encode::Error> {
        let version = LLMQVersion::consensus_decode(reader)?;
        let llmq_type = LLMQType::consensus_decode(reader)?;
        let llmq_hash = Decodable::consensus_decode(reader)?;
        let index = if version.use_rotated_quorums() {
            u16::consensus_decode(reader)?
        } else { u16::MAX };
        let signers = Decodable::consensus_decode(reader)?;
        let valid_members = Decodable::consensus_decode(reader)?;
        let public_key = Decodable::consensus_decode(reader)?;
        let verification_vector_hash = Decodable::consensus_decode(reader)?;
        let threshold_signature = Decodable::consensus_decode(reader)?;
        let all_commitment_aggregated_signature = Decodable::consensus_decode(reader)?;
        let entry = LLMQEntry::new(
            version,
            llmq_type,
            llmq_hash,
            index,
            signers,
            valid_members,
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature,
        );
        Ok(entry)
    }
}


impl<'a> TryRead<'a, Endian> for LLMQEntry {
    fn try_read(bytes: &'a [u8], _ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let version = bytes.read_with::<LLMQVersion>(offset, LE)?;
        let llmq_type = bytes.read_with::<LLMQType>(offset, LE)?;
        let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?.0;
        let index = if version.use_rotated_quorums() {
            bytes.read_with::<u16>(offset, LE)?
        } else {
            u16::MAX
        };
        let signers = bytes.read_with::<Bitset>(offset, LE)?;
        let valid_members = bytes.read_with::<Bitset>(offset, LE)?;
        let public_key = bytes.read_with::<UInt384>(offset, LE)?.0;
        let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?.0;
        let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?.0;
        let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?.0;
        let entry = LLMQEntry::new(
            version,
            llmq_type,
            llmq_hash,
            index,
            signers,
            valid_members,
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature,
        );
        Ok((entry, *offset))
    }
}


impl LLMQEntry {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: LLMQVersion,
        llmq_type: LLMQType,
        llmq_hash: [u8; 32],
        index: u16,
        signers: Bitset,
        valid_members: Bitset,
        public_key: [u8; 48],
        verification_vector_hash: [u8; 32],
        threshold_signature: [u8; 96],
        all_commitment_aggregated_signature: [u8; 96],
    ) -> Self {
        let q_data = generate_data(
            u16::from(version),
            u8::from(llmq_type),
            llmq_hash,
            index,
            &signers,
            &valid_members,
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature,
        );
        Self {
            version,
            llmq_hash,
            index,
            public_key,
            threshold_signature,
            verification_vector_hash,
            all_commitment_aggregated_signature,
            llmq_type,
            signers,
            valid_members,
            entry_hash: sha256d::Hash::hash(q_data.as_ref()).to_byte_array(),
            verified: LLMQEntryValidationStatus::Unknown,
            saved: false,
            commitment_hash: None,
        }
    }

    pub fn generate_commitment_hash(&mut self) -> [u8; 32] {
        if self.commitment_hash.is_none() {
            self.commitment_hash = Some(sha256d::Hash::hash(self.commitment_data().as_ref()).to_byte_array());
        }
        self.commitment_hash.unwrap()
    }

    pub fn mark_as_saved(&mut self) {
        self.saved = true;
    }

    pub fn validate_bitset(bitset: &Bitset) -> bool {
        let Bitset { bitset, count } = bitset;
        if bitset.len() != (count + 7) / 8 {
            warn!(
                "Error: The byte size of the bitvectors ({}) must match “(quorumSize + 7) / 8 ({})",
                bitset.len(),
                (count + 7) / 8
            );
            return false;
        }
        let len = (bitset.len() * 8) as i32;
        let size = *count as i32;
        if len != size {
            let rem = len - size;
            let mask = !(0xff >> rem);
            let last_byte = match bitset.last() {
                Some(&last) => last as i32,
                None => 0,
            };
            if last_byte & mask != 0 {
                warn!("Error: No out-of-range bits should be set in byte representation of the bitvector");
                return false;
            }
        }
        true
    }

    // pub fn validate_payload(&self) -> LLMQPayloadValidationStatus {
    //     // The quorumHash must match the current DKG session
    //     // todo
    //     let is_valid_signers =
    //         Self::validate_bitset(&self.signers);
    //     if !is_valid_signers {
    //         warn!("Error: signers_bitset is invalid ({:?})", self.signers);
    //         return LLMQPayloadValidationStatus::InvalidSigners(self.signers.bitset.to_hex());
    //     }
    //     let is_valid_members =
    //         Self::validate_bitset(&self.valid_members);
    //     if !is_valid_members {
    //         warn!("Error: valid_members_bitset is invalid ({:?})", self.valid_members);
    //         return LLMQPayloadValidationStatus::InvalidMembers(self.valid_members.bitset.to_hex());
    //     }
    //     let quorum_threshold = self.llmq_type.threshold() as u64;
    //     // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
    //     let signers_bitset_true_bits_count = self.signers.true_bits_count();
    //     if signers_bitset_true_bits_count < quorum_threshold {
    //         warn!("Error: The number of set bits in the signers {} must be >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
    //         return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: signers_bitset_true_bits_count, threshold: quorum_threshold };
    //     }
    //     let valid_members_bitset_true_bits_count = self.valid_members.true_bits_count();
    //     if valid_members_bitset_true_bits_count < quorum_threshold {
    //         warn!("Error: The number of set bits in the valid members bitvector {} must be >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
    //         return LLMQPayloadValidationStatus::SignersBelowThreshold { actual: valid_members_bitset_true_bits_count, threshold: quorum_threshold };
    //     }
    //     LLMQPayloadValidationStatus::Ok
    // }

    // fn
}

#[ferment_macro::export]
impl LLMQEntry {
    pub fn to_data(&self) -> Vec<u8> {
        generate_data(
            u16::from(self.version),
            u8::from(self.llmq_type),
            self.llmq_hash,
            self.index,
            &self.signers,
            &self.valid_members,
            self.public_key,
            self.verification_vector_hash,
            self.threshold_signature,
            self.all_commitment_aggregated_signature,
        )
    }
    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_type = VarInt(u64::from(&self.llmq_type));
        *offset += llmq_type.consensus_encode(&mut buffer).unwrap();
        *offset += self.llmq_hash.consensus_encode(&mut buffer).unwrap();
        *offset += self.valid_members.consensus_encode(&mut buffer).unwrap();
        *offset += self.public_key.consensus_encode(&mut buffer).unwrap();
        *offset += self.verification_vector_hash.consensus_encode(&mut buffer).unwrap();
        buffer
    }

    pub fn ordering_hash_for_request_id(&self, request_id: [u8; 32]) -> [u8; 32] {
        let llmq_type = VarInt(u64::from(&self.llmq_type));
        let mut writer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
        llmq_type.consensus_encode(&mut writer).unwrap();
        self.llmq_hash.consensus_encode(&mut writer).unwrap();
        request_id.consensus_encode(&mut writer).unwrap();
        sha256d::Hash::hash(&writer).to_byte_array()
    }

    // pub fn is_lock_sign_id(&self, request_id: [u8; 32], tx_hash: [u8; 32]) -> [u8; 32] {
    //     // let llmq_type = VarInt(chain_type.is_llmq_type() as u64);
    //     // let mut writer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
    //     // llmq_type.enc(&mut writer);
    //     // self.llmq_hash.enc(&mut writer);
    //     // request_id.enc(&mut writer);
    //     // tx_hash.enc(&mut writer);
    //     // sha256d::Hash::hash(&writer).into_inner()
    //     self.sign_id(request_id, tx_hash)
    //
    // }
    // pub fn chain_lock_sign_id(&self, request_id: [u8; 32], block_hash: [u8; 32]) -> [u8; 32] {
    //     // let llmq_type = VarInt(chain_type.chain_locks_type() as u64);
    //     // let mut writer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
    //     // llmq_type.enc(&mut writer);
    //     // self.llmq_hash.enc(&mut writer);
    //     // request_id.enc(&mut writer);
    //     // block_hash.enc(&mut writer);
    //     // sha256d::Hash::hash(&writer).into_inner()
    //     self.sign_id(request_id, block_hash)
    // }

    pub fn sign_id(&self, request_id: [u8; 32], payload: [u8; 32]) -> [u8; 32] {
        let llmq_type = VarInt(u64::from(&self.llmq_type));
        let mut writer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
        llmq_type.consensus_encode(&mut writer).unwrap();
        self.llmq_hash.consensus_encode(&mut writer).unwrap();
        request_id.consensus_encode(&mut writer).unwrap();
        payload.consensus_encode(&mut writer).unwrap();
        sha256d::Hash::hash(&writer).to_byte_array()
    }

    pub fn platform_sign_id(&self, height: u32, state_msg_hash: [u8; 32]) -> [u8; 32] {
        let mut request_id_writer = Vec::new();
        "dpsvote".to_string().consensus_encode(&mut request_id_writer).unwrap();
        (height as u64).consensus_encode(&mut request_id_writer).unwrap();
        let request_id = sha256::Hash::hash(&request_id_writer).to_byte_array().reversed();
        // let llmq_type = VarInt(self.llmq_type.index() as u64);
        self.sign_id(request_id, state_msg_hash.reversed())
        // let mut writer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
        // llmq_type.enc(&mut writer);
        // self.llmq_hash.enc(&mut writer);
        // request_id.reversed().enc(&mut writer);
        // state_msg_hash.reversed().enc(&mut writer);
        // sha256d::Hash::hash(&writer).into_inner()
    }


    pub fn verify_signature(&self, sign_id: [u8; 32], signature: [u8; 96]) -> bool {
        let sig = cfg!(debug_assertions).then(|| signature.to_lower_hex_string()).unwrap_or("<REDACTED>".to_string());
        let verified = BLSKey::verify_signature(self.public_key.clone(), self.version.use_bls_legacy(), &sign_id, signature);
        let sign_id = cfg!(debug_assertions).then(|| sign_id.to_lower_hex_string()).unwrap_or("<REDACTED>".to_string());
        info!("llmq::verify_signature ({}): {:?}: {}: {}: {}: {}: {}",
            verified,
            self.llmq_type,
            self.verified,
            sign_id,
            self.public_key.to_lower_hex_string(),
            sig,
            self.version.use_bls_legacy());
        verified
    }

    pub fn verify_cl_signature(&self, request_id: [u8; 32], block_hash: [u8; 32], signature: [u8; 96]) -> bool {
        let sign_id = self.sign_id(request_id, block_hash);
        BLSKey::verify_message_with_pub_key(&self.public_key, &sign_id, &signature, self.version.use_bls_legacy())
    }

    // pub fn verify_is_lock_signature_with_offset(&self, request_id: [u8; 32], tx_hash: [u8; 32], signature: [u8; 96]) -> bool {
    //     let sign_id = self.sign_id(request_id, tx_hash);
    //     BLSKey::verify_message_with_pub_key(&self.public_key, &sign_id, &signature, self.version.use_bls_legacy())
    // }

    pub fn llmq_hash_hex(&self) -> String {
        self.llmq_hash.to_lower_hex_string()
    }

    pub fn print_description(&self) {
        println!("{}", self)
    }

    pub fn is_verified(&self) -> bool {
        self.verified.is_verified()
    }
    pub fn is_not_verified(&self) -> bool {
        self.verified.is_not_verified()
    }
}

#[ferment_macro::export]
pub fn new(
    version: u16,
    llmq_type: u8,
    llmq_hash: [u8; 32],
    index: u16,
    signers: Bitset,
    valid_members: Bitset,
    public_key: [u8; 48],
    verification_vector_hash: [u8; 32],
    threshold_signature: [u8; 96],
    all_commitment_aggregated_signature: [u8; 96],
) -> LLMQEntry {
    LLMQEntry::new(
        LLMQVersion::from(version),
        LLMQType::from(llmq_type),
        llmq_hash,
        index,
        signers,
        valid_members,
        public_key,
        verification_vector_hash,
        threshold_signature,
        all_commitment_aggregated_signature,
    )
}
#[ferment_macro::export]
pub fn from_entity(
    version: u16,
    llmq_type: u8,
    llmq_hash: [u8; 32],
    index: u16,
    signers: Vec<u8>,
    signers_count: usize,
    valid_members: Vec<u8>,
    valid_members_count: usize,
    public_key: [u8; 48],
    verification_vector_hash: [u8; 32],
    threshold_signature: [u8; 96],
    all_commitment_aggregated_signature: [u8; 96],
    verified: LLMQEntryValidationStatus,
    entry_hash: Option<[u8; 32]>
) -> LLMQEntry {
    let signers = Bitset { count: signers_count, bitset: signers };
    let valid_members = Bitset { count: valid_members_count, bitset: valid_members };
    let entry_hash = entry_hash.unwrap_or_else(|| {
        let q_data = generate_data(
            version,
            llmq_type,
            llmq_hash,
            index,
            &signers,
            &valid_members,
            public_key,
            verification_vector_hash,
            threshold_signature,
            all_commitment_aggregated_signature,
        );
        sha256d::Hash::hash(q_data.as_ref()).to_byte_array()
    });
    LLMQEntry {
        version: LLMQVersion::from(version),
        llmq_hash,
        index,
        public_key,
        threshold_signature,
        verification_vector_hash,
        all_commitment_aggregated_signature,
        llmq_type: LLMQType::from(llmq_type),
        signers,
        valid_members,
        entry_hash,
        verified,
        saved: true,
        commitment_hash: None,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn generate_data(
    version: u16,
    llmq_type: u8,
    llmq_hash: [u8; 32],
    index: u16,
    signers: &Bitset,
    valid_members: &Bitset,
    public_key: [u8; 48],
    verification_vector_hash: [u8; 32],
    threshold_signature: [u8; 96],
    all_commitment_aggregated_signature: [u8; 96],
) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let offset = &mut 0;
    *offset += version.consensus_encode(&mut buffer).unwrap();
    *offset += llmq_type.consensus_encode(&mut buffer).unwrap();
    *offset += llmq_hash.consensus_encode(&mut buffer).unwrap();
    if index != u16::MAX {
        *offset += index.consensus_encode(&mut buffer).unwrap();
    }
    *offset += signers.consensus_encode(&mut buffer).unwrap();
    *offset += valid_members.consensus_encode(&mut buffer).unwrap();
    *offset += public_key.consensus_encode(&mut buffer).unwrap();
    *offset += verification_vector_hash.consensus_encode(&mut buffer).unwrap();
    *offset += threshold_signature.consensus_encode(&mut buffer).unwrap();
    *offset += all_commitment_aggregated_signature.consensus_encode(&mut buffer).unwrap();
    buffer
}
