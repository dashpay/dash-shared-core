#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct AccountEntity {
    pub index: i32,
    pub wallet_unique_id: String,
}
