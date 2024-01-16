use crate::models::transaction_destination::TransactionDestination;

pub(crate) struct CompactTallyItem {
    pub tx_destination: TransactionDestination,
    pub amount: u64,
    pub input_coins: Vec<InputCoin>,
}

impl CompactTallyItem {
    fn new(tx_destination: TransactionDestination) -> Self {
        CompactTallyItem {
            tx_destination,
            amount: 0,
            input_coins: Vec::new(),
        }
    }
}