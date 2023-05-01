use byte::{BytesExt, LE};
use crate::crypto::byte_util::BytesDecodable;
use crate::impl_bytes_decodable;

pub mod coinbase_transaction;
pub mod transaction;

pub use self::coinbase_transaction::CoinbaseTransaction;
pub use self::transaction::Transaction;
pub use self::transaction::TransactionInput;
pub use self::transaction::TransactionOutput;
pub use self::transaction::TransactionType;
pub use self::transaction::TX_UNCONFIRMED;

impl_bytes_decodable!(TransactionInput);
impl_bytes_decodable!(TransactionOutput);
impl_bytes_decodable!(Transaction);
impl_bytes_decodable!(CoinbaseTransaction);
