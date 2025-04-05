use crate::coin_selection::input_coin::InputCoin;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CompactTallyItem {
    pub tx_destination: Option<Vec<u8>>,
    pub amount: u64,
    pub input_coins: Vec<InputCoin>,
}

#[ferment_macro::export]
impl CompactTallyItem {
    pub fn new(tx_destination: Option<Vec<u8>>) -> CompactTallyItem {
        CompactTallyItem {
            tx_destination,
            amount: 0,
            input_coins: Vec::new(),
        }
    }
}
