#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InvitationLinkInfo {
    pub link: String,
    pub name: Option<String>,
    pub tag: Option<String>,
}

impl InvitationLinkInfo {
    pub(crate) fn new(link: String, name: Option<String>, tag: Option<String>) -> InvitationLinkInfo {
        Self { link, name, tag }
    }
}

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct InvitationCallbacks {
    // pub
}

#[derive(Clone)]
#[ferment_macro::opaque]
pub struct InvitationController {
    pub model: InvitationModel,
    pub callbacks: InvitationCallbacks,
}

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct InvitationModel {
    pub link: Option<InvitationLinkInfo>,
    pub is_transient: bool,
    pub needs_identity_retrieval: bool,
    pub created_locally: bool,
    pub identity_id: Option<[u8; 32]>,
    pub wallet_id: Option<String>,
}

#[ferment_macro::export]
impl InvitationModel {
    pub fn link(&self) -> Option<InvitationLinkInfo> {
        self.link.clone()
    }
    pub fn is_transient(&self) -> bool {
        self.is_transient
    }
    pub fn needs_identity_retrieval(&self) -> bool {
        self.needs_identity_retrieval
    }
    pub fn created_locally(&self) -> bool {
        self.created_locally
    }
    pub fn identity_id(&self) -> Option<[u8; 32]> {
        self.identity_id
    }
    pub fn wallet_id(&self) -> Option<String> {
        self.wallet_id.clone()
    }

}

impl InvitationModel {

    pub fn with_identity_and_entity(identity_id: [u8; 32], wallet_id: String, link_info: InvitationLinkInfo) -> InvitationModel {
        Self::new(Some(link_info), false, false, true, Some(identity_id), Some(wallet_id))
    }
    pub fn with_identity(identity_id: [u8; 32], wallet_id: String) -> InvitationModel {
        Self::new(None, false, false, true, Some(identity_id), Some(wallet_id))
    }

    pub fn with_index(
        wallet_id: String
    ) -> InvitationModel {
        Self::new(None, false, false, true, None, Some(wallet_id))
    }
    // pub fn with_index_and_asset_lock_transaction_model(
    //     index: u32,
    //     asset_lock_transaction_model: AssetLockTransactionModel,
    //     wallet_id: String
    // ) -> InvitationModel {
    //     Self::new(None, false, false, true, None, Some(wallet_id))
    //     // invitation.link_identity(IdentityModel::with_index_and_asset_lock_transaction_model(index, asset_lock_transaction_model, wallet_context))
    // }
    // pub fn with_index_and_locked_outpoint(
    //     index: u32,
    //     locked_outpoint: [u8; 36],
    //     controller: InvitationController,
    //     wallet_context: *const c_void
    // ) -> Arc<Mutex<InvitationModel>> {
    //     let invitation = Self::new(None, false, false, true, None, controller, wallet_context);
    //     invitation.link_identity(IdentityModel::with_index_and_locked_outpoint(index, locked_outpoint, wallet_context))
    // }
    //
    // pub fn with_index_and_locked_outpoint_and_entity(
    //     index: u32,
    //     locked_outpoint: [u8; 36],
    //     entity: InvitationEntity,
    //     controller: InvitationController,
    //     wallet_context: *const c_void
    // ) -> InvitationModel {
    //     let mut invitation = Self::new(None, false, false, true, None, controller, wallet_context);
    //     invitation.link = Some(InvitationLinkInfo {
    //         link: entity.link,
    //         name: entity.name,
    //         tag: entity.tag,
    //     });
    //     let invitation_mutex = Arc::new(Mutex::new(invitation));
    //     let identity = IdentityModel::with_index_and_locked_outpoint_and_entity_and_invitation(index, locked_outpoint, entity.identity_entity, Arc::downgrade(&invitation_mutex), wallet_context);
    //     let identity_mutex = Arc::new(Mutex::new(identity));
    //     invitation_mutex.lock().unwrap().identity = Some(identity_mutex.clone());
    //     invitation_mutex
    // }
    //
    // fn link_identity(self, mut identity: IdentityModel) -> Arc<Mutex<InvitationModel>> {
    //     let invitation_mutex = Arc::new(Mutex::new(self));
    //     identity.set_local_associated_invitation(Arc::downgrade(&invitation_mutex));
    //     let identity_mutex = Arc::new(Mutex::new(identity));
    //     invitation_mutex.lock().unwrap().identity = Some(identity_mutex.clone());
    //     invitation_mutex
    // }
}

#[ferment_macro::export]
impl InvitationModel {
    pub fn new(
        link: Option<InvitationLinkInfo>,
        is_transient: bool,
        needs_identity_retrieval: bool,
        created_locally: bool,
        identity_id: Option<[u8; 32]>,
        wallet_id: Option<String>,
    ) -> InvitationModel {
        Self { link, is_transient , needs_identity_retrieval, created_locally, identity_id, wallet_id }
    }

    pub fn with_link(link: InvitationLinkInfo, wallet_id: String) -> InvitationModel {
        Self::new(Some(link), false, true, false, None, Some(wallet_id))
    }

    // pub fn register_in_wallet_for_asset_lock_transaction(&mut self, transaction: TransactionModel) {
    //     if let Some(identity) = self.identity.as_mut() {
    //         let mut lock = identity.lock().unwrap();
    //         lock.set_invitation_asset_lock_transaction(transaction);
    //
    //         // [self registerInWallet];
    //         // we need to also set the address of the funding transaction to being used so future identities past the initial gap limit are found
    //         // [transaction markInvitationAddressAsUsedInWallet:self.wallet];
    //
    //     }
    // }
    //
    // pub fn identity_unique_id(&self) -> [u8; 32] {
    //     if let Some(identity) = &self.identity {
    //         let lock = identity.lock().unwrap();
    //         let unique_id = lock.unique_id();
    //         drop(lock);
    //         unique_id
    //     } else {
    //         [0; 32] // or handle the case where identity is None
    //     }
    // }
    // pub fn identity_locked_outpoint(&self) -> Option<OutPoint> {
    //     if let Some(identity) = &self.identity {
    //         let lock = identity.lock().unwrap();
    //         let unique_id = lock.locked_outpoint();
    //         drop(lock);
    //         unique_id
    //     } else {
    //         None
    //     }
    // }
    //
    // pub fn identity_index(&self) -> u32 {
    //     if let Some(identity) = &self.identity {
    //         let lock = identity.lock().unwrap();
    //         let index = lock.index();
    //         drop(lock);
    //         index
    //     } else {
    //         0 // or handle the case where identity is None
    //     }
    // }

}