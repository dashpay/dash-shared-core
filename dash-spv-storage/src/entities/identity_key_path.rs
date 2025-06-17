#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct IdentityKeyPathEntity {
    pub key_id: u32,
    pub key_status: u8,
    pub key_type: u16,
    pub path: Vec<u32>,
    pub public_key_data: Vec<u8>,
    pub purpose: u8,
    pub security_level: u8,
}
