#[derive(Debug, Clone)]
pub struct Recipient {
    pub script_pub_key: Option<Vec<u8>>,
    pub amount: u64,
    pub subtract_fee_from_amount: bool
}
