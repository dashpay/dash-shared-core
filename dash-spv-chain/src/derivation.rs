use std::os::raw::c_void;
use std::sync::Arc;
use dash_spv_crypto::derivation::derivation_path_kind::DerivationPathKind;

pub trait DerivationRef {
    fn derivation_ref(&self) -> &DerivationController;
}

pub struct DerivationController {
    pub get_derivation_path: Arc<dyn Fn(*const c_void, DerivationPathKind) -> *const c_void + Send + Sync>,
    pub get_public_key_data_at_index_path: Arc<dyn Fn(*const c_void, Vec<u32>) -> Vec<u8> + Send + Sync>,
    pub get_address_at_index_path: Arc<dyn Fn(*const c_void, Vec<u32>) -> String + Send + Sync>,
    pub has_extended_public_key_for_derivation_path_of_kind: Arc<dyn Fn(*const c_void, DerivationPathKind) -> bool + Send + Sync>,
    pub get_standalone_extended_public_key_unique_id: Arc<dyn Fn(*const c_void) -> String + Send + Sync>,

    pub get_wallet_based_extended_private_key_location_string: Arc<dyn Fn(*const c_void) -> String + Send + Sync>,

    mark_address_as_used: Arc<dyn Fn(*const c_void, /*address*/String)>,

}

impl DerivationController {
    pub fn new<
        GetDerivationPath: Fn(/*wallet_context*/ *const c_void, DerivationPathKind) -> *const c_void + Send + Sync + 'static,
        GetPublicKeyDataAtIndexPath: Fn(/*derivation_context*/*const c_void, Vec<u32>) -> Vec<u8> + Send + Sync + 'static,
        GetAddressAtIndexPath: Fn(/*derivation_context*/*const c_void, Vec<u32>) -> String + Send + Sync + 'static,
        HasExtendedPublicKeyForDerivationPathOfKind: Fn(/*wallet_context*/*const c_void, DerivationPathKind) -> bool + Send + Sync + 'static,
        GetStandaloneExtendedPublicKeyUniqueId: Fn(/*derivation_context*/*const c_void) -> String + Send + Sync + 'static,
        GetWalletBasedExtendedPrivateKeyLocationString: Fn(/*derivation_context*/*const c_void) -> String + Send + Sync + 'static,
        MarkAddressAsUsed: Fn(/*derivation_context*/*const c_void, String) + Send + Sync + 'static,
    >(
        get_derivation_path: GetDerivationPath,
        get_public_key_data_at_index_path: GetPublicKeyDataAtIndexPath,
        get_address_at_index_path: GetAddressAtIndexPath,
        has_extended_public_key_for_derivation_path_of_kind: HasExtendedPublicKeyForDerivationPathOfKind,
        get_standalone_extended_public_key_unique_id: GetStandaloneExtendedPublicKeyUniqueId,
        get_wallet_based_extended_private_key_location_string: GetWalletBasedExtendedPrivateKeyLocationString,
        mark_address_as_used: MarkAddressAsUsed,
    ) -> DerivationController {
        Self {
            get_derivation_path: Arc::new(get_derivation_path),
            get_public_key_data_at_index_path: Arc::new(get_public_key_data_at_index_path),
            get_address_at_index_path: Arc::new(get_address_at_index_path),
            has_extended_public_key_for_derivation_path_of_kind: Arc::new(has_extended_public_key_for_derivation_path_of_kind),
            get_standalone_extended_public_key_unique_id: Arc::new(get_standalone_extended_public_key_unique_id),
            get_wallet_based_extended_private_key_location_string: Arc::new(get_wallet_based_extended_private_key_location_string),
            mark_address_as_used: Arc::new(mark_address_as_used),
        }
    }

    pub fn derivation_path_for_wallet(&self, wallet_context: *const c_void, kind: DerivationPathKind) -> *const c_void {
        (self.get_derivation_path)(wallet_context, kind)
    }

    pub fn public_key_for_wallet_data_at_index_path(&self, wallet_context: *const c_void, kind: DerivationPathKind, index_path: Vec<u32>) -> Vec<u8> {
        let derivation_context = self.derivation_path_for_wallet(wallet_context, kind);
        (self.get_public_key_data_at_index_path)(derivation_context, index_path)
    }

    pub fn has_extended_public_key_for_derivation_path_of_kind(&self, wallet_context: *const c_void, kind: DerivationPathKind) -> bool {
        (self.has_extended_public_key_for_derivation_path_of_kind)(wallet_context, kind)
    }

    pub fn public_key_data_at_index_path(&self, derivation_context: *const c_void, index_path: Vec<u32>) -> Vec<u8> {
        (self.get_public_key_data_at_index_path)(derivation_context, index_path)
    }

    pub fn standalone_extended_public_key_unique_id(&self, derivation_context: *const c_void) -> String {
        (self.get_standalone_extended_public_key_unique_id)(derivation_context)
    }

    pub fn wallet_based_extended_private_key_location_string(&self, derivation_context: *const c_void) -> String {
        (self.get_wallet_based_extended_private_key_location_string)(derivation_context)
    }

    pub fn address_at_index_path(&self, derivation_context: *const c_void, index_path: Vec<u32>) -> String {
        (self.get_address_at_index_path)(derivation_context, index_path)
    }

    pub fn mark_address_as_used(&self, derivation_context: *const c_void, address: String) {
        (self.mark_address_as_used)(derivation_context, address)
    }
}
