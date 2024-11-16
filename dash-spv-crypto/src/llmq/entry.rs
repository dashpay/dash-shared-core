use std::io;
use byte::ctx::Endian;
use byte::{BytesExt, TryRead, LE};
use log::warn;
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
use crate::consensus::{Decodable, encode, encode::VarInt, Encodable};
use crate::crypto::{UInt256, UInt384, UInt768};
use crate::impl_bytes_decodable;
use crate::llmq::{Bitset, LLMQVersion};
use crate::network::LLMQType;

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
impl_bytes_decodable!(LLMQEntry);

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


    pub fn to_data(&self) -> Vec<u8> {
        generate_data(
            self.version,
            self.llmq_type,
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
        llmq_type: LLMQType,
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
}

#[allow(clippy::too_many_arguments)]
pub fn generate_data(
    version: LLMQVersion,
    llmq_type: LLMQType,
    llmq_hash: UInt256,
    index: Option<u16>,
    signers: &Bitset,
    valid_members: &Bitset,
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
