use crate::models::tx_destination::TxDestination;
use crate::coin_selection::input_coin::InputCoin;

#[derive(Clone, Debug)]
pub struct CompactTallyItem {
    pub tx_destination: TxDestination,
    pub amount: u64,
    pub input_coins: Vec<InputCoin>,
}

// impl CompactTallyItem {
//     fn new(tx_destination: TxDestination) -> Self {
//         CompactTallyItem {
//             tx_destination,
//             amount: 0,
//             input_coins: Vec::new(),
//         }
//     }
// }
