use std::fmt::Debug;
use crate::util::cc_crypt::{aes256_encrypt_decrypt, Operation};
use crate::keys::{IKey, KeyError};

pub const CC_BLOCK_SIZE_AES128: usize = 16;

pub trait DHKey: Send + Sync + Debug {
    fn init_with_dh_key_exchange_with_public_key(public_key: &mut Self, private_key: &Self) -> Result<Self, KeyError> where Self: Sized;
}
// TODO: CryptoData where AsRef<[u8]>: CryptoData<K>
pub trait CryptoData<K: IKey + Clone>: Send + Sync + Debug where Vec<u8>: CryptoData<K> {

    #[inline]
    fn random_initialization_vector_of_size(size: usize) -> Vec<u8> {
        use secp256k1::rand;
        use secp256k1::rand::distributions::Uniform;
        use secp256k1::rand::Rng;
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, 255);
        (0..size).map(|_| rng.sample(&range)).collect()
    }

    fn encrypt(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Vec<u8>, KeyError> {
        aes256_encrypt_decrypt(Operation::Encrypt, data, key, iv)
    }

    fn decrypt(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Vec<u8>, KeyError> {
        aes256_encrypt_decrypt(Operation::Decrypt, data, key, iv)
    }

    fn encrypt_with_secret_key(&mut self, secret_key: &K, public_key: &K) -> Result<Vec<u8>, KeyError> {
        self.encrypt_with_secret_key_using_iv(secret_key, public_key, Self::random_initialization_vector_of_size(CC_BLOCK_SIZE_AES128))
    }

    fn encrypt_with_secret_key_using_iv(&mut self, secret_key: &K, public_key: &K, initialization_vector: Vec<u8>) -> Result<Vec<u8>, KeyError>;

    fn decrypt_with_secret_key(&mut self, secret_key: &K, public_key: &K) -> Result<Vec<u8>, KeyError> {
        self.decrypt_with_secret_key_using_iv_size(secret_key, public_key, CC_BLOCK_SIZE_AES128)
    }

    fn decrypt_with_secret_key_using_iv_size(&mut self, secret_key: &K, public_key: &K, iv_size: usize) -> Result<Vec<u8>, KeyError>;


    // DHKey
    fn encrypt_with_dh_key(&self, key: &K) -> Result<Vec<u8>, KeyError> where K: DHKey {
        self.encrypt_with_dh_key_using_iv(key, Self::random_initialization_vector_of_size(CC_BLOCK_SIZE_AES128))
    }
    fn encrypt_with_dh_key_using_iv(&self, key: &K, initialization_vector: Vec<u8>) -> Result<Vec<u8>, KeyError> where K: DHKey;
    fn decrypt_with_dh_key(&self, key: &K) -> Result<Vec<u8>, KeyError> where K: DHKey {
        self.decrypt_with_dh_key_using_iv_size(key, CC_BLOCK_SIZE_AES128)
    }
    fn decrypt_with_dh_key_using_iv_size(&self, key: &K, iv_size: usize) -> Result<Vec<u8>, KeyError> where K: DHKey;



    // Chained sequence

    fn encapsulated_dh_decryption_with_keys(&mut self, keys: Vec<K>) -> Result<Vec<u8>, KeyError> where K: DHKey {
        assert!(keys.len() > 0, "There should be at least one key");
        match &keys[..] {
            [first_key, other @ ..] if !other.is_empty() =>
                self.decrypt_with_dh_key(first_key)
                    .and_then(|mut data| data.encapsulated_dh_decryption_with_keys(other.to_vec())),
            [first_key] =>
                self.decrypt_with_dh_key(first_key),
            _ => Err(KeyError::DHKeyExchange)
        }
    }

    fn encapsulated_dh_decryption_with_keys_using_iv_size(&mut self, keys: Vec<K>, iv_size: usize) -> Result<Vec<u8>, KeyError> where K: DHKey {
        assert!(keys.len() > 1, "There should be at least two key (first pair)");
        match &keys[..] {
            [first_key, other @ ..] if other.len() > 1 =>
                self.decrypt_with_secret_key_using_iv_size(other.first().unwrap(), first_key, iv_size)
                    .and_then(|mut data| data.encapsulated_dh_decryption_with_keys_using_iv_size(other.to_vec(), iv_size)),
            [first_key, second_key] =>
                self.decrypt_with_secret_key_using_iv_size(second_key, first_key, iv_size),
            _ => Err(KeyError::DHKeyExchange)
        }
    }

    fn encapsulated_dh_encryption_with_keys(&mut self, keys: Vec<K>) -> Result<Vec<u8>, KeyError> where K: DHKey {
        assert!(!keys.is_empty(), "There should be at least one key");
        match &keys[..] {
            [first, other @ ..] if !other.is_empty() =>
                self.encrypt_with_dh_key(first)
                    .and_then(|mut data| data.encapsulated_dh_encryption_with_keys(other.to_vec())),
            [first] => self.encrypt_with_dh_key(first),
            _ => Err(KeyError::DHKeyExchange)
        }
    }

    fn encapsulated_dh_encryption_with_keys_using_iv(&mut self, keys: Vec<K>, initialization_vector: Vec<u8>) -> Result<Vec<u8>, KeyError> where K: DHKey {
        assert!(!keys.is_empty(), "There should be at least one key");
        match &keys[..] {
            [first, other @ ..] if !other.is_empty() =>
                self.encrypt_with_dh_key(first)
                    .and_then(|mut data| data.encapsulated_dh_encryption_with_keys_using_iv(other.to_vec(), initialization_vector)),
            [first] => self.encrypt_with_dh_key(first),
            _ => Err(KeyError::DHKeyExchange)
        }
    }
}

