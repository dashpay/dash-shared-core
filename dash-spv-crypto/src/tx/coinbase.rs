// use crate::tx::{Transaction, TransactionType};
//
//
// pub const COINBASE_TX_CORE_19: u16 = 2;
// pub const COINBASE_TX_CORE_20: u16 = 3;
//
// #[derive(Debug, Clone)]
// #[ferment_macro::export]
// pub struct CoinbaseTransaction {
//     pub base: Transaction,
//     pub coinbase_transaction_version: u16,
//     pub height: u32,
//     pub merkle_root_mn_list: [u8; 32],
//     pub merkle_root_llmq_list: Option<[u8; 32]>,
//     pub best_cl_height_diff: u64,
//     pub best_cl_signature: Option<[u8; 96]>,
//     pub credit_pool_balance: Option<i64>,
// }
//
// impl dashcore::consensus::Decodable for CoinbaseTransaction {
//     #[inline]
//     fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, dashcore::consensus::encode::Error> {
//         let mut base = Transaction::consensus_decode(reader)?;
//         let _extra_payload_size = VarInt::consensus_decode(reader)?;
//         let coinbase_transaction_version = u16::consensus_decode(reader)?;
//         let height = u32::consensus_decode(reader)?;
//         let merkle_root_mn_list = <[u8; 32]>::consensus_decode(reader)?;
//
//         let merkle_root_llmq_list = if coinbase_transaction_version >= 2 {
//             Some(<[u8; 32]>::consensus_decode(reader)?)
//         } else {
//             None
//         };
//         let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if coinbase_transaction_version >= 3 {
//             (
//                 VarInt::consensus_decode(reader)?.0,
//                 <[u8; 96]>::consensus_decode(reader).ok(),
//                 i64::consensus_decode(reader).ok())
//         } else {
//             (u64::MAX, None, None)
//         };
//         base.tx_type = TransactionType::Coinbase;
//         let mut tx = Self {
//             base,
//             coinbase_transaction_version,
//             height,
//             merkle_root_mn_list,
//             merkle_root_llmq_list,
//             best_cl_height_diff,
//             best_cl_signature,
//             credit_pool_balance,
//         };
//         tx.base.tx_hash = Some(UInt256::sha256d(tx.to_data()).0);
//         Ok(tx)
//     }
// }

// impl<'a> TryRead<'a, Endian> for CoinbaseTransaction {
//     fn try_read(bytes: &'a [u8], endian: Endian) -> byte::Result<(Self, usize)> {
//         let offset = &mut 0;
//         let mut base = bytes.read_with::<Transaction>(offset, endian)?;
//         let _extra_payload_size = bytes.read_with::<VarInt>(offset, endian)?;
//         let coinbase_transaction_version = bytes.read_with::<u16>(offset, endian)?;
//         let height = bytes.read_with::<u32>(offset, endian)?;
//         let merkle_root_mn_list = bytes.read_with::<UInt256>(offset, endian)?.0;
//         let merkle_root_llmq_list = if coinbase_transaction_version >= COINBASE_TX_CORE_19 {
//             let root = bytes.read_with::<UInt256>(offset, endian)?.0;
//             Some(root)
//         } else {
//             None
//         };
//         let (best_cl_height_diff, best_cl_signature, credit_pool_balance) = if coinbase_transaction_version >= COINBASE_TX_CORE_20 {
//             (bytes.read_with::<VarInt>(offset, byte::LE)?.0,
//              bytes.read_with::<UInt768>(offset, byte::LE).map(|x|x.0).ok(),
//              bytes.read_with::<i64>(offset, byte::LE).ok())
//
//         } else {
//             (u64::MAX, None, None)
//         };
//         base.tx_type = TransactionType::Coinbase;
//         base.payload_offset = *offset;
//         let mut tx = Self {
//             base,
//             coinbase_transaction_version,
//             height,
//             merkle_root_mn_list,
//             merkle_root_llmq_list,
//             best_cl_height_diff,
//             best_cl_signature,
//             credit_pool_balance
//         };
//         tx.base.tx_hash = Some(UInt256::sha256d(tx.to_data()).0);
//         Ok((tx, *offset))
//     }
// }
//
// impl CoinbaseTransaction {
//     fn payload_data(&self) -> Vec<u8> {
//         let mut buffer: Vec<u8> = Vec::new();
//         self.coinbase_transaction_version.consensus_encode(&mut buffer).unwrap();
//         self.height.consensus_encode(&mut buffer).unwrap();
//         self.merkle_root_mn_list.consensus_encode(&mut buffer).unwrap();
//
//         if self.coinbase_transaction_version >= COINBASE_TX_CORE_19 {
//             if let Some(llmq_root) = self.merkle_root_llmq_list {
//                 llmq_root.consensus_encode(&mut buffer).unwrap();
//             }
//             if self.coinbase_transaction_version >= COINBASE_TX_CORE_20 {
//                 VarInt(self.best_cl_height_diff).consensus_encode(&mut buffer).unwrap();
//                 if let Some(cl_sig) = self.best_cl_signature {
//                     cl_sig.consensus_encode(&mut buffer).unwrap();
//                 }
//                 if let Some(credit_pool_balance) = self.credit_pool_balance {
//                     credit_pool_balance.consensus_encode(&mut buffer).unwrap();
//                 }
//             }
//         }
//         buffer
//     }
//
//     pub fn to_data(&self) -> Vec<u8> {
//         self.to_data_with_subscript_index(u64::MAX)
//     }
//
//     pub fn to_data_with_subscript_index(&self, subscript_index: u64) -> Vec<u8> {
//         let mut buffer = Transaction::data_with_subscript_index_static(
//             subscript_index,
//             self.base.version,
//             self.base.tx_type.clone(),
//             &self.base.inputs,
//             &self.base.outputs,
//             self.base.lock_time,
//         );
//         let payload = self.payload_data();
//         payload.consensus_encode(&mut buffer).unwrap();
//         buffer
//     }
//
//     pub fn has_found_coinbase(&mut self, hashes: &[[u8; 32]]) -> bool {
//         let coinbase_hash = self.base.tx_hash.unwrap_or_else(|| {
//             let hash = sha256d::Hash::hash(&self.to_data()).to_byte_array();
//             self.base.tx_hash = Some(hash);
//             hash
//         });
//         self.has_found_coinbase_internal(coinbase_hash, hashes)
//     }
//
//     fn has_found_coinbase_internal(&self, coinbase_hash: [u8; 32], hashes: &[[u8; 32]]) -> bool {
//         hashes.iter().any(|h| coinbase_hash == *h)
//     }
// }

