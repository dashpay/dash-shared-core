pub mod input;
pub mod output;
pub mod tx;
pub mod coinbase;
pub mod credit_funding;

// use crate::impl_bytes_decodable;
pub use self::input::TransactionInput;
pub use self::output::TransactionOutput;
pub use self::tx::{ITransaction, Transaction, TransactionType};
// pub use self::coinbase::{CoinbaseTransaction, COINBASE_TX_CORE_19, COINBASE_TX_CORE_20};

// impl_bytes_decodable!(TransactionInput);
// impl_bytes_decodable!(TransactionOutput);
// impl_bytes_decodable!(Transaction);
// impl_bytes_decodable!(CoinbaseTransaction);
