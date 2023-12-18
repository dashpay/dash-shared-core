use std::io;
use std::io::{Error, Write};
use dash_spv_masternode_processor::crypto::UInt256;
use dash_spv_masternode_processor::consensus::{Decodable, Encodable, encode};
use dash_spv_masternode_processor::tx::Transaction;

// dstx
#[repr(C)]
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct CoinJoinBroadcastTx {
    pub tx: Transaction,
    // pub transaction_outpoint: TransactionOutPoint, // TODO: versioning
    pub pro_tx_hash: UInt256,
    pub signature: Option<Vec<u8>>,
    pub signature_time: i64,
}

impl Encodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_encode<W: Write>(&self, mut writer: W) -> Result<usize, Error> {
        let mut offset = 0;
        let tx_data = self.tx.to_data(); // TODO: consensus_encode
        writer.write_all(&tx_data)?;
        offset += tx_data.len();

        // TODO: versioning
        // if (protocolVersion >= params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.COINJOIN_PROTX_HASH)) {
            offset += self.pro_tx_hash.consensus_encode(&mut writer)?;
        // } else {
        //     masternodeOutpoint.bitcoinSerialize(stream);
        // }

        offset += match self.signature {
            Some(ref signature) => signature.consensus_encode(&mut writer)?,
            None => 0
        };
        offset += self.signature_time.consensus_encode(&mut writer)?;

        Ok(offset)
    }
}

impl Decodable for CoinJoinBroadcastTx {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        let tx = Transaction::consensus_decode(&mut d)?;

        // TODO: versioning
        // if (protocolVersion >= params.getProtocolVersionNum(NetworkParameters.ProtocolVersion.COINJOIN_PROTX_HASH)) {
            let pro_tx_hash = UInt256::consensus_decode(&mut d)?;
        // } else {
        //     masternodeOutpoint.bitcoinSerialize(stream);
        // }

        let signature: Option<Vec<u8>> = Vec::consensus_decode(&mut d).ok();
        let signature_time = i64::consensus_decode(&mut d)?;

        Ok(CoinJoinBroadcastTx { tx, pro_tx_hash, signature, signature_time })
    }
}
