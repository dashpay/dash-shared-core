#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct AddressEntity {
    pub address: String,
    pub identity_index: i32,
    pub index: i32,
    pub internal: bool,
    pub standalone: bool,
}
