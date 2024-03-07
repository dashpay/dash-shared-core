use super::input_coin::InputCoin;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct GatheredOutputs {
    pub items: *mut *mut InputCoin,
    pub item_count: usize,
}