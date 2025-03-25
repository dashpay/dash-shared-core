#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[ferment_macro::export]
pub enum PoolStatusUpdate {
    Rejected = 0,
    Accepted = 1,
}

#[ferment_macro::export]
impl PoolStatusUpdate {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_value(value: i32) -> PoolStatusUpdate {
        match value {
            0 => PoolStatusUpdate::Rejected,
            _ => PoolStatusUpdate::Accepted,
        }
    }
}
