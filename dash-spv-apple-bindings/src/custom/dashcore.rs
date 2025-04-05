use crate::fermented::generics::{Arr_u8_20, Arr_u8_32};
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
pub struct dashcore_hash_types_BlockHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::BlockHash, dashcore_hash_types_BlockHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::CycleHash)]
pub struct dashcore_hash_types_CycleHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::CycleHash, dashcore_hash_types_CycleHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::Txid)]
pub struct dashcore_hash_types_Txid(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::Txid, dashcore_hash_types_Txid);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::PubkeyHash)]
pub struct dashcore_hash_types_PubkeyHash(*mut Arr_u8_20);
impl_hash_ferment!(dashcore::hash_types::PubkeyHash, dashcore_hash_types_PubkeyHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ScriptHash)]
pub struct dashcore_hash_types_ScriptHash(*mut Arr_u8_20);
impl_hash_ferment!(dashcore::hash_types::ScriptHash, dashcore_hash_types_ScriptHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::TxMerkleNode)]
pub struct dashcore_hash_types_TxMerkleNode(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::TxMerkleNode, dashcore_hash_types_TxMerkleNode);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::SpecialTransactionPayloadHash)]
pub struct dashcore_hash_types_SpecialTransactionPayloadHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::SpecialTransactionPayloadHash, dashcore_hash_types_SpecialTransactionPayloadHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::InputsHash)]
pub struct dashcore_hash_types_InputsHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::InputsHash, dashcore_hash_types_InputsHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumHash)]
pub struct dashcore_hash_types_QuorumHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::QuorumHash, dashcore_hash_types_QuorumHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumVVecHash)]
pub struct dashcore_hash_types_QuorumVVecHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::QuorumVVecHash, dashcore_hash_types_QuorumVVecHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumSigningRequestId)]
pub struct dashcore_hash_types_QuorumSigningRequestId(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::QuorumSigningRequestId, dashcore_hash_types_QuorumSigningRequestId);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ProTxHash)]
pub struct dashcore_hash_types_ProTxHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::ProTxHash, dashcore_hash_types_ProTxHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::MerkleRootMasternodeList)]
pub struct dashcore_hash_types_MerkleRootMasternodeList(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::MerkleRootMasternodeList, dashcore_hash_types_MerkleRootMasternodeList);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::MerkleRootQuorums)]
pub struct dashcore_hash_types_MerkleRootQuorums(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::MerkleRootQuorums, dashcore_hash_types_MerkleRootQuorums);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumEntryHash)]
pub struct dashcore_hash_types_QuorumEntryHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::QuorumEntryHash, dashcore_hash_types_QuorumEntryHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ConfirmedHashHashedWithProRegTx)]
pub struct dashcore_hash_types_ConfirmedHashHashedWithProRegTx(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::ConfirmedHashHashedWithProRegTx, dashcore_hash_types_ConfirmedHashHashedWithProRegTx);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::ConfirmedHash)]
pub struct dashcore_hash_types_ConfirmedHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::ConfirmedHash, dashcore_hash_types_ConfirmedHash);
#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::QuorumCommitmentHash)]
pub struct dashcore_hash_types_QuorumCommitmentHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::QuorumCommitmentHash, dashcore_hash_types_QuorumCommitmentHash);

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::hash_types::Sha256dHash)]
pub struct dashcore_hash_types_Sha256dHash(*mut Arr_u8_32);
impl_hash_ferment!(dashcore::hash_types::Sha256dHash, dashcore_hash_types_Sha256dHash);


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
