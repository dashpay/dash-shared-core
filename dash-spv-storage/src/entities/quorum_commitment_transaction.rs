use crate::entities::special_transaction::SpecialTransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct QuorumCommitmentTransactionEntity {
    pub base: SpecialTransactionEntity,
    pub quorum_commitment_type: i32,
}

