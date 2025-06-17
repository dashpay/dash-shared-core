#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum Predicate {
    DashPayUserEntity {
        identity_id: [u8; 32]
    },
    DeleteIdentity {
        identity_id: [u8; 32],
    },
    DeleteInvitation {
        identity_id: [u8; 32],
    },
    DeleteInvitations {
        identity_ids: Vec<[u8; 32]>,
    },
    GetIdentityByIdentityId {
        identity_id: [u8; 32],
    },
    GetInvitationByIdentityId {
        identity_id: [u8; 32],
    },
    GetAssetLockTransactionByTxHash {
        tx_hash: [u8; 32],
    },

    KeyPathContext {
        wallet_id: String,
        identity_id: [u8; 32],
        derivation_path_kind: u32,
        index_path: Vec<u32>
    }
}

impl Predicate {
    pub fn delete_identity(identity_id: &[u8; 32]) -> Predicate {
        Predicate::DeleteIdentity { identity_id: identity_id.clone() }
    }
    pub fn delete_invitation(identity_id: &[u8; 32]) -> Predicate {
        Predicate::DeleteInvitation { identity_id: identity_id.clone() }
    }
}