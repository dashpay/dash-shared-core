use crate::ffi::compact_tally_item::CompactTallyItem;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct SelectedCoins {
    pub items: *mut *mut CompactTallyItem,
    pub item_count: usize,
}