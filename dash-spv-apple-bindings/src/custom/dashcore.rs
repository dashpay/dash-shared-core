use dashcore::hashes::Hash;
use crate::impl_hash_ferment;

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::consensus::encode::Error)]
pub struct dashcore_consensus_Error(pub *mut dashcore::consensus::encode::Error);
impl ferment::FFIConversionFrom<dashcore::consensus::encode::Error> for dashcore_consensus_Error {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::consensus::encode::Error {
        *ferment::unbox_any((&*ffi).0)
    }
}
impl ferment::FFIConversionTo<dashcore::consensus::encode::Error> for dashcore_consensus_Error {
    unsafe fn ffi_to_const(obj: dashcore::consensus::encode::Error) -> *const Self {
        ferment::boxed(Self(ferment::boxed(obj.into())))
    }
}

impl Drop for dashcore_consensus_Error {
    fn drop(&mut self) {
        unsafe { ferment::unbox_any(self.0); }
    }
}
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::BlockHash)]
pub struct dashcore_hash_types_BlockHash(pub *mut [u8; dashcore::hash_types::BlockHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::BlockHash,
    dashcore_hash_types_BlockHash,
    dashcore_hash_types_BlockHash_ctor,
    dashcore_hash_types_BlockHash_destroy,
    dashcore_hash_types_BlockHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::CycleHash)]
pub struct dashcore_hash_types_CycleHash(pub *mut [u8; dashcore::hash_types::CycleHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::CycleHash,
    dashcore_hash_types_CycleHash,
    dashcore_hash_types_CycleHash_ctor,
    dashcore_hash_types_CycleHash_destroy,
    dashcore_hash_types_CycleHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::Txid)]
pub struct dashcore_hash_types_Txid(pub *mut [u8; dashcore::hash_types::Txid::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::Txid,
    dashcore_hash_types_Txid,
    dashcore_hash_types_Txid_ctor,
    dashcore_hash_types_Txid_destroy,
    dashcore_hash_types_Txid_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::PubkeyHash)]
pub struct dashcore_hash_types_PubkeyHash(pub *mut [u8; dashcore::hash_types::PubkeyHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::PubkeyHash,
    dashcore_hash_types_PubkeyHash,
    dashcore_hash_types_PubkeyHash_ctor,
    dashcore_hash_types_PubkeyHash_destroy,
    dashcore_hash_types_PubkeyHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ScriptHash)]
pub struct dashcore_hash_types_ScriptHash(pub *mut [u8; dashcore::hash_types::ScriptHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::ScriptHash,
    dashcore_hash_types_ScriptHash,
    dashcore_hash_types_ScriptHash_ctor,
    dashcore_hash_types_ScriptHash_destroy,
    dashcore_hash_types_ScriptHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::TxMerkleNode)]
pub struct dashcore_hash_types_TxMerkleNode(pub *mut [u8; dashcore::hash_types::TxMerkleNode::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::TxMerkleNode,
    dashcore_hash_types_TxMerkleNode,
    dashcore_hash_types_TxMerkleNode_ctor,
    dashcore_hash_types_TxMerkleNode_destroy,
    dashcore_hash_types_TxMerkleNode_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::SpecialTransactionPayloadHash)]
pub struct dashcore_hash_types_SpecialTransactionPayloadHash(pub *mut [u8; dashcore::hash_types::SpecialTransactionPayloadHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::SpecialTransactionPayloadHash,
    dashcore_hash_types_SpecialTransactionPayloadHash,
    dashcore_hash_types_SpecialTransactionPayloadHash_ctor,
    dashcore_hash_types_SpecialTransactionPayloadHash_destroy,
    dashcore_hash_types_SpecialTransactionPayloadHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::InputsHash)]
pub struct dashcore_hash_types_InputsHash(pub *mut [u8; dashcore::hash_types::InputsHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::InputsHash,
    dashcore_hash_types_InputsHash,
    dashcore_hash_types_InputsHash_ctor,
    dashcore_hash_types_InputsHash_destroy,
    dashcore_hash_types_InputsHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumHash)]
pub struct dashcore_hash_types_QuorumHash(pub *mut [u8; dashcore::hash_types::QuorumHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::QuorumHash,
    dashcore_hash_types_QuorumHash,
    dashcore_hash_types_QuorumHash_ctor,
    dashcore_hash_types_QuorumHash_destroy,
    dashcore_hash_types_QuorumHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumVVecHash)]
pub struct dashcore_hash_types_QuorumVVecHash(pub *mut [u8; dashcore::hash_types::QuorumVVecHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::QuorumVVecHash,
    dashcore_hash_types_QuorumVVecHash,
    dashcore_hash_types_QuorumVVecHash_ctor,
    dashcore_hash_types_QuorumVVecHash_destroy,
    dashcore_hash_types_QuorumVVecHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumSigningRequestId)]
pub struct dashcore_hash_types_QuorumSigningRequestId(pub *mut [u8; dashcore::hash_types::QuorumSigningRequestId::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::QuorumSigningRequestId,
    dashcore_hash_types_QuorumSigningRequestId,
    dashcore_hash_types_QuorumSigningRequestId_ctor,
    dashcore_hash_types_QuorumSigningRequestId_destroy,
    dashcore_hash_types_QuorumSigningRequestId_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ProTxHash)]
pub struct dashcore_hash_types_ProTxHash(pub *mut [u8; dashcore::hash_types::ProTxHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::ProTxHash,
    dashcore_hash_types_ProTxHash,
    dashcore_hash_types_ProTxHash_ctor,
    dashcore_hash_types_ProTxHash_destroy,
    dashcore_hash_types_ProTxHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::MerkleRootMasternodeList)]
pub struct dashcore_hash_types_MerkleRootMasternodeList(pub *mut [u8; dashcore::hash_types::MerkleRootMasternodeList::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::MerkleRootMasternodeList,
    dashcore_hash_types_MerkleRootMasternodeList,
    dashcore_hash_types_MerkleRootMasternodeList_ctor,
    dashcore_hash_types_MerkleRootMasternodeList_destroy,
    dashcore_hash_types_MerkleRootMasternodeList_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::MerkleRootQuorums)]
pub struct dashcore_hash_types_MerkleRootQuorums(pub *mut [u8; dashcore::hash_types::MerkleRootQuorums::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::MerkleRootQuorums,
    dashcore_hash_types_MerkleRootQuorums,
    dashcore_hash_types_MerkleRootQuorums_ctor,
    dashcore_hash_types_MerkleRootQuorums_destroy,
    dashcore_hash_types_MerkleRootQuorums_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumEntryHash)]
pub struct dashcore_hash_types_QuorumEntryHash(pub *mut [u8; dashcore::hash_types::QuorumEntryHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::QuorumEntryHash,
    dashcore_hash_types_QuorumEntryHash,
    dashcore_hash_types_QuorumEntryHash_ctor,
    dashcore_hash_types_QuorumEntryHash_destroy,
    dashcore_hash_types_QuorumEntryHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ConfirmedHashHashedWithProRegTx)]
pub struct dashcore_hash_types_ConfirmedHashHashedWithProRegTx(pub *mut [u8; dashcore::hash_types::ConfirmedHashHashedWithProRegTx::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::ConfirmedHashHashedWithProRegTx,
    dashcore_hash_types_ConfirmedHashHashedWithProRegTx,
    dashcore_hash_types_ConfirmedHashHashedWithProRegTx_ctor,
    dashcore_hash_types_ConfirmedHashHashedWithProRegTx_destroy,
    dashcore_hash_types_ConfirmedHashHashedWithProRegTx_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ConfirmedHash)]
pub struct dashcore_hash_types_ConfirmedHash(pub *mut [u8; dashcore::hash_types::ConfirmedHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::ConfirmedHash,
    dashcore_hash_types_ConfirmedHash,
    dashcore_hash_types_ConfirmedHash_ctor,
    dashcore_hash_types_ConfirmedHash_destroy,
    dashcore_hash_types_ConfirmedHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumCommitmentHash)]
pub struct dashcore_hash_types_QuorumCommitmentHash(pub *mut [u8; dashcore::hash_types::QuorumCommitmentHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::QuorumCommitmentHash,
    dashcore_hash_types_QuorumCommitmentHash,
    dashcore_hash_types_QuorumCommitmentHash_ctor,
    dashcore_hash_types_QuorumCommitmentHash_destroy,
    dashcore_hash_types_QuorumCommitmentHash_inner);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::Sha256dHash)]
pub struct dashcore_hash_types_Sha256dHash(pub *mut [u8; dashcore::hash_types::Sha256dHash::LEN]);
impl_hash_ferment!(
    dashcore::hash_types::Sha256dHash,
    dashcore_hash_types_Sha256dHash,
    dashcore_hash_types_Sha256dHash_ctor,
    dashcore_hash_types_Sha256dHash_destroy,
    dashcore_hash_types_Sha256dHash_inner);

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dashcore::hashes::hex::Error)]
pub enum hashes_hex_Error_FFI {
    InvalidChar(u8),
    OddLengthString(usize),
    InvalidLength(usize, usize),
}
// use

impl ferment::FFIConversionFrom<dashcore::hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn ffi_from_const(ffi: *const hashes_hex_Error_FFI) -> dashcore::hashes::hex::Error {
        let ffi_ref = &*ffi;
        match ffi_ref {
            hashes_hex_Error_FFI::InvalidChar(o_0) => dashcore::hashes::hex::Error::InvalidChar(*o_0),
            hashes_hex_Error_FFI::OddLengthString(o_0) => dashcore::hashes::hex::Error::OddLengthString(*o_0),
            hashes_hex_Error_FFI::InvalidLength(o_0, o_1) => dashcore::hashes::hex::Error::InvalidLength(*o_0, *o_1),
        }
    }
}
impl ferment::FFIConversionTo<dashcore::hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn ffi_to_const(obj: dashcore::hashes::hex::Error) -> *const hashes_hex_Error_FFI {
        ferment::boxed(match obj {
            dashcore::hashes::hex::Error::InvalidChar(o_0) => hashes_hex_Error_FFI::InvalidChar(o_0),
            dashcore::hashes::hex::Error::OddLengthString(o_0) => hashes_hex_Error_FFI::OddLengthString(o_0),
            dashcore::hashes::hex::Error::InvalidLength(o_0, o_1) => hashes_hex_Error_FFI::InvalidLength(o_0, o_1),
        })
    }
}
impl ferment::FFIConversionDestroy<dashcore::hashes::hex::Error> for hashes_hex_Error_FFI {
    unsafe fn destroy(ffi: *mut hashes_hex_Error_FFI) {
        ferment::unbox_any(ffi);
    }
}
