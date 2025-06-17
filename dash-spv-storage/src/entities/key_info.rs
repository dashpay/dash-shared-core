#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct KeyInfoEntity {
    pub index_path: Option<Vec<u32>>,
    pub key_id: u32,
    pub key_kind: i16,
    pub key_status: u8,
    pub public_key_data: Vec<u8>,
    pub purpose: u8,
    pub security_level: u8,
}