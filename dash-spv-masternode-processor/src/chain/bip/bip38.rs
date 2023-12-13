use bip38::{Decrypt, Encrypt};
use byte::BytesExt;
use crate::chain::ScriptMap;
use crate::crypto::byte_util::UInt256;
use crate::keys::{ECDSAKey, KeyError};
use crate::util::base58;

const BIP38_NOEC_PREFIX: u16 = 0x0142;
const BIP38_EC_PREFIX: u16 = 0x0143;
const BIP38_NOEC_FLAG: u8 = 0x80 | 0x40;
const BIP38_COMPRESSED_FLAG: u8 = 0x20;
const BIP38_LOTSEQUENCE_FLAG: u8 = 0x04;
const BIP38_INVALID_FLAG: u8 = 0x10 | 0x08 | 0x02 | 0x01;

pub trait BIP38 {
    // decrypts a BIP38 key using the given passphrase or retuns nil if passphrase is incorrect
    fn key_with_bip38_key(key: &str, passphrase: &str, script: &ScriptMap) -> Result<Self, KeyError> where Self: Sized;
    // generates an "intermediate code" for an EC multiply mode key, salt should be 64bits of random data
    // fn bip38_intermediate_code_with_salt(salt: u64, passphrase: &str) -> Option<String>;
    // generates an "intermediate code" for an EC multiply mode key with a lot and sequence number, lot must be less than
    // 1048576, sequence must be less than 4096, and salt should be 32bits of random data
    // fn bip38_intermediate_code_with_lot(lot: u32, sequence: u16, salt: u32, passphrase: &str) -> Option<String>;
    // generates a BIP38 key from an "intermediate code" and 24 bytes of cryptographically random data (seedb),
    // fn bip38_key_with_intermediate_code(code: &str, seedb: Vec<u8>, chain_type: ChainType) -> Option<String>;
    // encrypts receiver with passphrase and returns BIP38 key
    fn bip38_key_with_passphrase(&self, passphrase: &str, script: &ScriptMap) -> Result<String, KeyError>;

    fn is_valid_bip38_key(key: &str) -> bool;
}

impl BIP38 for ECDSAKey {

    fn key_with_bip38_key(key: &str, passphrase: &str, script: &ScriptMap) -> Result<Self, KeyError> where Self: Sized {
        key.decrypt(passphrase, script.pubkey)
            .map_err(KeyError::from)
            .and_then(|(secret, compressed)| ECDSAKey::init_with_secret(UInt256(secret), compressed))
    }

    fn bip38_key_with_passphrase(&self, passphrase: &str, script: &ScriptMap) -> Result<String, KeyError> {
        self.seckey.0.encrypt(passphrase, false, script.pubkey)
            .map_err(KeyError::from)
    }

    fn is_valid_bip38_key(key: &str) -> bool {
        match base58::from_check(key) {
            Ok(d) if d.len() == 39 => {
                if let Ok(prefix) = d.read_with::<u16>(&mut 0, byte::BE) {
                    let flag = d[2];
                    if prefix == BIP38_NOEC_PREFIX { // non EC multiplied key
                        flag & BIP38_NOEC_FLAG == BIP38_NOEC_FLAG && flag & BIP38_LOTSEQUENCE_FLAG == 0 && flag & BIP38_INVALID_FLAG == 0
                    } else if prefix == BIP38_EC_PREFIX { // EC multiplied key
                        flag & BIP38_NOEC_FLAG == 0 && flag & BIP38_INVALID_FLAG == 0
                    } else {
                        false
                    }
                } else {
                    false
                }
            },
            _ => false
        }
    }
}
