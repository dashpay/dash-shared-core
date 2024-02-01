use crate::ffi::input_coin::InputCoin;
use crate::coin_selection::compact_tally_item;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct CompactTallyItem {
    pub tx_destination: *mut u8,
    pub tx_destination_length: usize,
    pub amount: u64,
    pub input_coins: *mut *mut InputCoin,
    pub input_coins_size: usize
}

impl CompactTallyItem {
    pub unsafe fn decode(&self) -> compact_tally_item::CompactTallyItem {
        compact_tally_item::CompactTallyItem {
            tx_destination: if self.tx_destination_length == 0 || self.tx_destination.is_null() {
                None
            } else {
                Some(std::slice::from_raw_parts(self.tx_destination, self.tx_destination_length).to_vec())
            },
            input_coins: (0..self.input_coins_size)
                .into_iter()
                .map(|i| (*(*self.input_coins.add(i))).decode())
                .collect(),
            amount: self.amount
        }
    }    
}
