use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::ffi::from::FromFFI;
use dash_spv_masternode_processor::types::TransactionOutput;
use crate::coin_selection::input_coin;
use crate::models::tx_outpoint::TxOutPoint;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct InputCoin {
    pub outpoint_hash: *mut [u8; 32],
    pub outpoint_index: u32,
    pub output: *mut TransactionOutput,
    pub effective_value: u64
}

impl InputCoin {
    pub unsafe fn decode(&self) -> input_coin::InputCoin {
        input_coin::InputCoin {
            tx_outpoint: TxOutPoint {
                hash: UInt256(*self.outpoint_hash),
                index: self.outpoint_index
            },
            output: (*self.output).decode(),
            effective_value: self.effective_value
        }
    }
}
