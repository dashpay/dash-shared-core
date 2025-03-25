use dash_spv_crypto::util::params::DUFFS;

pub trait CoinFormat {
    fn to_friendly_string(self) -> String;
}

impl CoinFormat for i64 {
    fn to_friendly_string(self) -> String {
        let sign = if self < 0 { "-" } else { "" };
        let abs_amount = self.abs();
        let quotient = abs_amount / DUFFS as i64;
        let remainder = abs_amount % DUFFS as i64;
    
        if remainder == 0 {
            format!("{}{}", sign, quotient)
        } else {
            let decimal_part = format!("{:08}", remainder).trim_end_matches('0').to_string();
            format!("{}{}.{}", sign, quotient, decimal_part)
        }
    }
}

impl CoinFormat for u64 {
    fn to_friendly_string(self) -> String {
        let quotient = self / DUFFS;
        let remainder = self % DUFFS;
    
        if remainder == 0 {
            format!("{}", quotient)
        } else {
            let decimal_part = format!("{:08}", remainder).trim_end_matches('0').to_string();
            format!("{}.{}", quotient, decimal_part)
        }
    }
}