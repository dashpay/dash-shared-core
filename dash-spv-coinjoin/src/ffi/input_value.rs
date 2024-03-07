#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct InputValue {
    pub is_valid: bool,
    pub value: u64,
}