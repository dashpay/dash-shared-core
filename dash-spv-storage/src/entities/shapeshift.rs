use crate::entities::transaction::TransactionEntity;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ShapeshiftEntity {
    pub error_message: Option<String>,
    pub expires_at: Option<u64>,
    pub input_address: Option<String>,
    pub input_coin_amount: f64,
    pub input_coin_type: Option<String>,
    pub is_fixed_amount: bool,
    pub output_coin_amount: f64,
    pub output_coin_type: Option<String>,
    pub output_transaction_id: Option<String>,
    pub shapeshift_status: i16,
    pub withdrawal_address: Option<String>,

    pub transaction: Option<Box<TransactionEntity>>,
}
