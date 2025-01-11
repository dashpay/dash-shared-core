use dpp::data_contract::DataContract;
use dash_spv_crypto::network::ChainType;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum ContractState {
    Unknown,
    NotRegistered,
    Registered,
    Registering,
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ContractModel {
    pub chain_type: ChainType,
    pub data_contract: DataContract,
    pub state: ContractState,
    pub local_identifier: String,
}

// impl ContractModel {
//     pub fn system(contract: SystemDataContract, version: &PlatformVersion, chain_type: ChainType) -> Result<ContractModel, ProtocolError> {
//         load_system_data_contract(contract, version).map(|loaded| Self {
//             data_contract: loaded,
//             // state: ContractState::Unknown,
//             chain_type,
//             local_identifier: format!("{}_CONTRACT-{}", match contract {
//                 SystemDataContract::Withdrawals => "Withdrawals",
//                 SystemDataContract::MasternodeRewards => "MasternodeRewards",
//                 SystemDataContract::FeatureFlags => "FeatureFlags",
//                 SystemDataContract::DPNS => "DPNS",
//                 SystemDataContract::Dashpay => "Dashpay",
//                 SystemDataContract::WalletUtils => "WalletUtils"
//             }, chain_type.unique_id())
//         })
//     }
// }
//
