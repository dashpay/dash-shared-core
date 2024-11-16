mod input;
mod output;
mod tx;
mod coinbase;

use crate::impl_bytes_decodable;
pub use self::input::TransactionInput;
pub use self::output::TransactionOutput;
pub use self::tx::{ITransaction, Transaction, TransactionType};
pub use self::coinbase::{CoinbaseTransaction, COINBASE_TX_CORE_19, COINBASE_TX_CORE_20};

impl_bytes_decodable!(TransactionInput);
impl_bytes_decodable!(TransactionOutput);
impl_bytes_decodable!(Transaction);
impl_bytes_decodable!(CoinbaseTransaction);
