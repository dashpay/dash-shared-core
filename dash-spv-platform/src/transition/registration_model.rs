use dashcore::{InstantLock, OutPoint, Txid};
use dpp::identity::state_transition::asset_lock_proof::chain::ChainAssetLockProof;
use dpp::identity::state_transition::asset_lock_proof::InstantAssetLockProof;
use dash_spv_chain::TransactionModel;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct RegistrationTransitionModel {
    pub transaction_model: TransactionModel,
    pub instant_lock: Option<InstantLock>,
    pub is_transient: bool,
}



#[ferment_macro::export]
impl RegistrationTransitionModel {
    pub fn new(transaction_model: TransactionModel, instant_lock: Option<InstantLock>, is_transient: bool) -> RegistrationTransitionModel {
        Self {
            transaction_model,
            instant_lock,
            is_transient,
        }
    }
    pub fn asset_lock_tx_id(&self) -> Txid {
        self.transaction_model.transaction.txid()
    }

    pub fn create_instant_proof(&self) -> InstantAssetLockProof {
        InstantAssetLockProof {
            instant_lock: self.instant_lock.clone().unwrap(),
            transaction: self.transaction_model.transaction.clone(),
            output_index: 0,
        }
    }

    pub fn create_chain_proof(&self) -> ChainAssetLockProof {
        ChainAssetLockProof {
            core_chain_locked_height: self.transaction_model.core_chain_locked_height,
            out_point: OutPoint::new(self.asset_lock_tx_id(), 0),
        }
    }

}
