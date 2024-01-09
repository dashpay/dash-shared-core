#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PoolStatusUpdate {
    StatusRejected = 0,
    StatusAccepted = 1,
}

impl PoolStatusUpdate {
    pub fn value(&self) -> i32 {
        *self as i32
    }

    pub fn from_value(value: i32) -> Self {
        match value {
            0 => PoolStatusUpdate::StatusRejected,
            _ => PoolStatusUpdate::StatusAccepted,
        }
    }
}
