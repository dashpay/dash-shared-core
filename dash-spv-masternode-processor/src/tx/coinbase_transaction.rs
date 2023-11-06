use byte::ctx::Endian;
use byte::{BytesExt, TryRead};
use crate::consensus::encode::VarInt;
use crate::consensus::Encodable;
use crate::crypto::{UInt256, UInt768};
use crate::tx::{Transaction, TransactionType::Coinbase};


pub const COINBASE_TX_CORE_19: u16 = 2;
pub const COINBASE_TX_CORE_20: u16 = 3;

#[derive(Debug, Clone)]
pub struct CoinbaseTransaction {
    pub base: Transaction,
    pub coinbase_transaction_version: u16,
    pub height: u32,
    pub merkle_root_mn_list: UInt256,
    pub merkle_root_llmq_list: Option<UInt256>,
    pub best_cl_height_diff: u64,
    pub best_cl_signature: Option<UInt768>,
    pub credit_pool_balance: Option<i64>,
}

impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
    fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let mut base = bytes.read_with::<Transaction>(offset, endian)?;
        let _extra_payload_size = bytes.read_with::<VarInt>(offset, endian)?;
        let coinbase_transaction_version = bytes.read_with::<u16>(offset, endian)?;
        let height = bytes.read_with::<u32>(offset, endian)?;
        let merkle_root_mn_list = bytes.read_with::<UInt256>(offset, endian)?;
        let merkle_root_llmq_list = if coinbase_transaction_version >= COINBASE_TX_CORE_19 {
            let root = bytes.read_with::<UInt256>(offset, endian)?;
            Some(root)
        } else {
            None
        };
        let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if coinbase_transaction_version >= COINBASE_TX_CORE_20 {
            (bytes.read_with::<VarInt>(offset, byte::LE)?.0,
            bytes.read_with::<UInt768>(offset, byte::LE).ok(),
            bytes.read_with::<i64>(offset, byte::LE).ok())

        } else {
            (u64::MAX, None, None)
        };
        base.tx_type = Coinbase;
        base.payload_offset = *offset;
        let mut tx = Self {
            base,
            coinbase_transaction_version,
            height,
            merkle_root_mn_list,
            merkle_root_llmq_list,
            best_cl_height_diff,
            best_cl_signature,
            credit_pool_balance
        };
        tx.base.tx_hash = Some(UInt256::sha256d(tx.to_data()));
        Ok((tx, *offset))
    }
}

impl CoinbaseTransaction {
    fn payload_data(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        self.coinbase_transaction_version.enc(&mut buffer);
        self.height.enc(&mut buffer);
        self.merkle_root_mn_list.enc(&mut buffer);

        if self.coinbase_transaction_version >= COINBASE_TX_CORE_19 {
            if let Some(llmq_root) = self.merkle_root_llmq_list {
                llmq_root.enc(&mut buffer);
            }
            if self.coinbase_transaction_version >= COINBASE_TX_CORE_20 {
                VarInt(self.best_cl_height_diff).enc(&mut buffer);
                if let Some(cl_sig) = self.best_cl_signature {
                    cl_sig.enc(&mut buffer);
                }
                if let Some(credit_pool_balance) = self.credit_pool_balance {
                    credit_pool_balance.enc(&mut buffer);
                }
            }
        }
        buffer
    }

    pub fn to_data(&self) -> Vec<u8> {
        self.to_data_with_subscript_index(u64::MAX)
    }

    pub fn to_data_with_subscript_index(&self, subscript_index: u64) -> Vec<u8> {
        let mut buffer = Transaction::data_with_subscript_index_static(
            subscript_index,
            self.base.version,
            self.base.tx_type,
            &self.base.inputs,
            &self.base.outputs,
            self.base.lock_time,
        );
        let payload = self.payload_data();
        payload.enc(&mut buffer);
        buffer
    }

    pub fn has_found_coinbase(&mut self, hashes: &[UInt256]) -> bool {
        let coinbase_hash = match self.base.tx_hash {
            Some(hash) => hash,
            None => {
                let hash = UInt256::sha256d(self.to_data());
                self.base.tx_hash = Some(hash);
                hash
            }
        };
        self.has_found_coinbase_internal(coinbase_hash, hashes)
    }

    fn has_found_coinbase_internal(&self, coinbase_hash: UInt256, hashes: &[UInt256]) -> bool {
        hashes.iter().any(|h| coinbase_hash == *h)
    }
}
