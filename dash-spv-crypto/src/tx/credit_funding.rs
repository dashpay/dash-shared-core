use byte::BytesExt;
use dashcore::{OutPoint, Txid, hashes::sha256d, TxOut};
use dashcore::hashes::Hash;
use dashcore::opcodes::all;
use crate::crypto::byte_util::Reversed;
use crate::tx::Transaction;
use crate::util::base58;

// @property (nonatomic, readonly) uint64_t fundingAmount;
// @property (nonatomic, readonly) UInt256 creditBurnIdentityIdentifier;
// @property (nonatomic, readonly) DSUTXO lockedOutpoint;
// @property (nonatomic, readonly) UInt160 creditBurnPublicKeyHash;
// @property (nonatomic, readonly) uint32_t usedDerivationPathIndex;
//

pub trait CreditFunding {
    fn locked_outpoint(&self) -> Option<OutPoint>;
    fn credit_burn_identity_identifier(&self) -> [u8; 32];
    fn credit_burn_identity_identifier_base58(&self) -> String {
        base58::encode_slice(&self.credit_burn_identity_identifier())
    }

    fn credit_burn_public_key_hash(&self) -> Option<[u8; 20]>;
}

impl CreditFunding for dashcore::Transaction {
    fn locked_outpoint(&self) -> Option<OutPoint> {
        self.output.iter().enumerate().find_map(|(i, TxOut { script_pubkey, .. })|
            match script_pubkey.first_opcode() {
                Some(all::OP_RETURN) if script_pubkey.len() == 22 =>
                    Some(OutPoint::new(self.txid(), i as u32)),
                _ => None
            })
    }

    fn credit_burn_identity_identifier(&self) -> [u8; 32] {
        if let Some(out) = self.locked_outpoint() {

            let data: [u8; 36] = out.into();
            return sha256d::Hash::hash(&data).to_byte_array()
        }
        [0u8; 32]
    }

    fn credit_burn_public_key_hash(&self) -> Option<[u8; 20]> {
        self.output.iter().find_map(|TxOut { script_pubkey, .. }|
            match script_pubkey.first_opcode() {
                Some(all::OP_RETURN) if script_pubkey.len() == 22 =>
                    (&script_pubkey.0[2..22]).try_into().ok(),
                _ => None
            })
    }
}

pub struct CreditFundingTransaction {
    pub base: Transaction,
    // pub funding_amount: u64,
    // // pub credit_burn_identity_identifier: [u8; 32],
    // pub locked_outpoint: OutPoint,
}

impl From<&[u8]> for CreditFundingTransaction {
    fn from(value: &[u8]) -> Self {
        let base = value.read_with::<Transaction>(&mut 0, byte::LE).unwrap();
        Self { base }
    }
}

impl CreditFundingTransaction {
    pub fn locked_outpoint(&self) -> Option<OutPoint> {
        self.base.outputs.iter().enumerate().find_map(|(i, output)| {
            if let Some(ref script) = output.script {
                if script[0] == 0x6a && script.len() == 22 {
                    let hash = self.base.tx_hash().unwrap().reversed();
                    let tx_id = Txid::from_slice(&hash).unwrap();
                    return Some(OutPoint::new(tx_id, i as u32))
                }
            }
            None
        })
    }
    pub fn credit_burn_identity_identifier(&self) -> [u8; 32] {
        if let Some(out) = self.locked_outpoint() {
            let data: [u8; 36] = out.into();
            return sha256d::Hash::hash(&data).to_byte_array()
        }
        [0u8; 32]
    }
    pub fn credit_burn_identity_identifier_base58(&self) -> String {
        base58::encode_slice(&self.credit_burn_identity_identifier())
    }

    pub fn credit_burn_public_key_hash(&self) -> Option<[u8; 20]> {
        self.base.outputs.iter().find_map(|output| {
            if let Some(ref script) = output.script {
                if script[0] == 0x6a && script.len() == 22 {
                    let chunk = &script[2..22];
                    return chunk.try_into().ok()
                }
            }
            None
        })
    }
}