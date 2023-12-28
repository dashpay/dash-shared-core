use dash_spv_masternode_processor::chain::params::DUFFS;

pub fn value_from_amount(amount: i64) -> String {
    let sign = if amount < 0 { "-" } else { "" };
    let abs_amount = amount.abs();
    let quotient = abs_amount / DUFFS as i64;
    let remainder = abs_amount % DUFFS as i64;
    
    if remainder == 0 {
        format!("{}{}", sign, quotient)
    } else {
        let decimal_part = format!("{:08}", remainder).trim_end_matches('0').to_string();
        format!("{}{}.{}", sign, quotient, decimal_part)
    }
}