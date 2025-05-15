use std::os::raw::c_void;
use std::sync::Arc;
use dpp::data_contract::DataContract;

#[ferment_macro::export]
pub enum ContractState {
    Unknown,
    NotRegistered,
    Registered,
    Registering,
}
#[ferment_macro::opaque]
pub struct ContractModel {
    pub contract: DataContract,
    pub state: ContractState,
    pub save: Arc<dyn Fn(*const c_void) -> bool>,
}

// impl ContractModel {
//     pub fn new(state: ContractState) -> ContractModel {
//         Self {
//             state,
//
//         }
//     }
// }