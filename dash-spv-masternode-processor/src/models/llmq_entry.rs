use std::convert::Into;
use std::io;
use byte::{BytesExt, TryRead, LE};
use byte::ctx::Endian;
use hashes::hex::ToHex;
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
use crate::chain::common::llmq_type::LLMQType;
use crate::common::{bitset::Bitset, llmq_version::LLMQVersion};
use crate::consensus::{encode::VarInt, Encodable, Decodable, encode};
use crate::crypto::{byte_util::AsBytes, UInt256, UInt384, UInt768};
use crate::keys::BLSKey;
use crate::models;


#[derive(Clone, Ord, PartialOrd, PartialEq, Eq)]
#[ferment_macro::export]
pub struct LLMQEntry {
    pub version: LLMQVersion,
    pub llmq_hash: UInt256,
    pub index: Option<u16>,
    pub public_key: UInt384,
    pub threshold_signature: UInt768,
    pub verification_vector_hash: UInt256,
    pub all_commitment_aggregated_signature: UInt768,
    pub llmq_type: LLMQType,
    pub signers: Bitset,
    pub valid_members: Bitset,
    pub entry_hash: UInt256,
    pub verified: bool,
    pub saved: bool,
    pub commitment_hash: Option<UInt256>,
}

#[cfg(feature = "generate-dashj-tests")]
impl Serialize for LLMQEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut state = serializer.serialize_struct("LLMQEntry", 10 + usize::from(self.index.is_some()))?;
        state.serialize_field("version", &self.version)?;
        if let Some(index) = self.index {
            state.serialize_field("index", &index)?;
        }
        state.serialize_field("public_key", &self.public_key)?;
        state.serialize_field("threshold_signature", &self.threshold_signature)?;
        state.serialize_field("verification_vector_hash", &self.verification_vector_hash)?;
        state.serialize_field("all_commitment_aggregated_signature", &self.all_commitment_aggregated_signature)?;
        state.serialize_field("llmq_type", &self.llmq_type)?;
        state.serialize_field("signers", &self.signers)?;
        state.serialize_field("valid_members", &self.valid_members)?;
        state.end()
    }
}

pub struct VecHex(pub Vec<u8>);
impl std::fmt::Debug for VecHex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Vec::from_hex(\"{}\").unwrap()", self.0.to_hex())
    }
}

impl std::fmt::Debug for LLMQEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQEntry")
            .field("version", &self.version)
            .field("llmq_hash", &self.llmq_hash)
            .field("index", &self.index)
            .field("public_key", &self.public_key)
            .field("threshold_signature", &self.threshold_signature)
            .field("verification_vector_hash", &self.verification_vector_hash)
            .field("all_commitment_aggregated_signature", &self.all_commitment_aggregated_signature)
            .field("llmq_type", &self.llmq_type)
            .field("signers", &self.signers)
            .field("valid_members", &self.valid_members)
            .field("entry_hash", &self.entry_hash)
            .field("verified", &self.verified)
            .field("saved", &self.saved)
            .field("commitment_hash", &self.commitment_hash)
            .finish()
    }
}

impl Encodable for LLMQEntry {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        len += self.llmq_type.consensus_encode(&mut s)?;
        len += self.llmq_hash.consensus_encode(&mut s)?;
        if self.version.use_rotated_quorums() {
            len += self.index.unwrap().consensus_encode(&mut s)?;
        }
        len += self.signers.consensus_encode(&mut s)?;
        len += self.valid_members.consensus_encode(&mut s)?;
        len += self.public_key.consensus_encode(&mut s)?;
        len += self.verification_vector_hash.consensus_encode(&mut s)?;
        len += self.threshold_signature.consensus_encode(&mut s)?;
        len += self.all_commitment_aggregated_signature.consensus_encode(&mut s)?;
        Ok(len)
    }
}

impl Decodable for LLMQEntry {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let version = LLMQVersion::consensus_decode(&mut d)?;
        let llmq_type = LLMQType::consensus_decode(&mut d)?;
        let llmq_hash = UInt256::consensus_decode(&mut d)?;
        let index = version.use_rotated_quorums().then_some(u16::consensus_decode(&mut d)?);
        let signers = Bitset::consensus_decode(&mut d)?;
        let valid_members = Bitset::consensus_decode(&mut d)?;
        let public_key = UInt384::consensus_decode(&mut d)?;
        let verification_vector_hash = UInt256::consensus_decode(&mut d)?;
        let threshold_signature = UInt768::consensus_decode(&mut d)?;
        let all_commitment_aggregated_signature = UInt768::consensus_decode(&mut d)?;
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
        let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let index = if version.use_rotated_quorums() {
            Some(bytes.read_with::<u16>(offset, LE)?)
        } else {
            None
        };
        let signers = bytes.read_with::<Bitset>(offset, LE)?;
        let valid_members = bytes.read_with::<Bitset>(offset, LE)?;
        let public_key = bytes.read_with::<UInt384>(offset, LE)?;
        let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?;
        let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?;
        let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?;
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
        llmq_hash: UInt256,
        index: Option<u16>,
        signers: Bitset,
        valid_members: Bitset,
        public_key: UInt384,
        verification_vector_hash: UInt256,
        threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768,
    ) -> Self {
        let q_data = Self::generate_data(
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
            entry_hash: UInt256::sha256d(q_data),
            verified: false,
            saved: false,
            commitment_hash: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn generate_data(
        version: crate::common::LLMQVersion,
        llmq_type: crate::chain::common::LLMQType,
        llmq_hash: UInt256,
        index: Option<u16>,
        signers: &crate::common::Bitset,
        valid_members: &crate::common::Bitset,
        public_key: UInt384,
        verification_vector_hash: UInt256,
        threshold_signature: UInt768,
        all_commitment_aggregated_signature: UInt768,
    ) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset = &mut 0;
        let llmq_u8: u8 = llmq_type.into();
        let llmq_v: u16 = version.into();
        *offset += llmq_v.enc(&mut buffer);
        *offset += llmq_u8.enc(&mut buffer);
        *offset += llmq_hash.enc(&mut buffer);
        if let Some(index) = index {
            *offset += index.enc(&mut buffer);
        }
        *offset += signers.enc(&mut buffer);
        *offset += valid_members.enc(&mut buffer);
        *offset += public_key.enc(&mut buffer);
        *offset += verification_vector_hash.enc(&mut buffer);
        *offset += threshold_signature.enc(&mut buffer);
        *offset += all_commitment_aggregated_signature.enc(&mut buffer);
        buffer
    }

    pub fn build_llmq_quorum_hash(
        llmq_type: crate::chain::common::LLMQType,
        llmq_hash: UInt256,
    ) -> UInt256 {
        let mut writer: Vec<u8> = Vec::with_capacity(33);
        VarInt(llmq_type as u64).enc(&mut writer);
        llmq_hash.enc(&mut writer);
        UInt256::sha256d(writer)
    }

    pub fn llmq_quorum_hash(&self) -> UInt256 {
        Self::build_llmq_quorum_hash(self.llmq_type, self.llmq_hash)
    }

    pub fn commitment_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        let offset: &mut usize = &mut 0;
        let llmq_type = VarInt(self.llmq_type as u64);
        *offset += llmq_type.enc(&mut buffer);
        *offset += self.llmq_hash.enc(&mut buffer);
        *offset += self.valid_members.enc(&mut buffer);
        *offset += self.public_key.enc(&mut buffer);
        *offset += self.verification_vector_hash.enc(&mut buffer);
        buffer
    }

    pub fn ordering_hash_for_request_id(
        &self,
        request_id: UInt256,
        llmq_type: crate::chain::common::LLMQType,
    ) -> UInt256 {
        let llmq_type = VarInt(llmq_type as u64);
        let mut buffer: Vec<u8> = Vec::with_capacity(llmq_type.len() + 64);
        llmq_type.enc(&mut buffer);
        self.llmq_hash.enc(&mut buffer);
        request_id.enc(&mut buffer);
        UInt256::sha256d(buffer)
    }

    pub fn generate_commitment_hash(&mut self) -> UInt256 {
        if self.commitment_hash.is_none() {
            self.commitment_hash = Some(UInt256::sha256d(self.commitment_data()));
        }
        self.commitment_hash.unwrap()
    }
   pub fn validate_payload(&self) -> bool {
        // The quorumHash must match the current DKG session
        // todo
        if !self.signers.is_valid() {
            warn!("Error: signers_bitset is invalid {:?}", self.signers);
            return false;
        }
        if !self.valid_members.is_valid() {
            warn!("Error: valid_members_bitset is invalid {:?}", self.valid_members);
            return false;
        }
        let quorum_threshold = self.llmq_type.threshold() as u64;
        // The number of set bits in the signers and validMembers bitvectors must be at least >= quorumThreshold
        let signers_bitset_true_bits_count = self.signers.true_bits_count();
        if signers_bitset_true_bits_count < quorum_threshold {
            warn!("Error: The number of set bits in the signers bitvector {} must be at least >= quorumThreshold {}", signers_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        let valid_members_bitset_true_bits_count = self.valid_members.true_bits_count();
        if valid_members_bitset_true_bits_count < quorum_threshold {
            warn!("Error: The number of set bits in the validMembers bitvector {} must be at least >= quorumThreshold {}", valid_members_bitset_true_bits_count, quorum_threshold);
            return false;
        }
        true
    }
}

impl LLMQEntry {
    pub fn verify(
        &mut self,
        valid_masternodes: Vec<models::MasternodeEntry>,
        block_height: u32,
    ) -> bool {
        if !self.validate_payload() {
            return false;
        }
        self.verified = self.validate(valid_masternodes, block_height);
        self.verified
    }

    pub fn validate(
        &mut self,
        valid_masternodes: Vec<models::MasternodeEntry>,
        block_height: u32,
    ) -> bool {
        let commitment_hash = self.generate_commitment_hash();
        let use_legacy = self.version.use_bls_legacy();

        let operator_keys = valid_masternodes
            .iter()
            .enumerate()
            .filter_map(|(i, node)|
                self.signers.bit_is_true_at_le_index(i)
                    .then_some(node.operator_public_key_at(block_height)))
            .collect::<Vec<_>>();
        // info!("let operator_keys = vec![{:?}];", operator_keys);
        let all_commitment_aggregated_signature_validated = BLSKey::verify_secure_aggregated(
            commitment_hash,
            self.all_commitment_aggregated_signature,
            operator_keys,
            use_legacy,
        );
        if !all_commitment_aggregated_signature_validated {
            // warn!("••• Issue with all_commitment_aggregated_signature_validated: {}", self.all_commitment_aggregated_signature);
            println!(
                "••• INVALID AGGREGATED SIGNATURE {}: {:?} ({})",
                block_height, self.llmq_type, self.all_commitment_aggregated_signature
            );
            return false;
        }
        // The sig must validate against the commitmentHash and all public keys determined by the signers bitvector.
        // This is an aggregated BLS signature verification.
        let quorum_signature_validated = BLSKey::verify_quorum_signature(
            commitment_hash.as_bytes(),
            self.threshold_signature.as_bytes(),
            self.public_key.as_bytes(),
            use_legacy,
        );
        if !quorum_signature_validated {
            println!(
                "••• INVALID QUORUM SIGNATURE {}: {:?} ({})",
                block_height, self.llmq_type, self.threshold_signature
            );
            // warn!("••• Issue with quorum_signature_validated");
            return false;
        }
        println!(
            "••• quorum {:?} validated at {}",
            self.llmq_type, block_height
        );
        true
    }
}
