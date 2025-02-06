#[repr(C)]
#[derive(Clone, Debug)]
pub struct InputValue {
    pub is_valid: bool,
    pub value: u64,
}