
#[ferment_macro::export]
pub enum CacheState {
    QueueChanged {
        count: usize,
        max_amount: usize,
    },
    StoreChanged {
        count: usize,
        last_block_height: u32
    },
    StubCount {
        count: usize
    },

}

impl CacheState {
    pub fn queue(count: usize, max_amount: usize) -> Self {
        Self::QueueChanged { count, max_amount }
    }
    pub fn store(count: usize, last_block_height: u32) -> Self {
        Self::StoreChanged { count, last_block_height }
    }
}