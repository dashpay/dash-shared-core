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

