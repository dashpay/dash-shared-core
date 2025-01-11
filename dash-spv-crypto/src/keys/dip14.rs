use ed25519_dalek::{SigningKey, VerifyingKey};
use secp256k1::Scalar;
use crate::consensus::encode::Encodable;
use crate::crypto::byte_util::{AsBytes, clone_into_array, UInt256, UInt512};
use crate::derivation::{BIP32_HARD, IIndexPath};
use crate::keys::{ECDSAKey, ED25519Key};

pub trait IChildKeyDerivationData<T, SK, PK> where SK: SignKey {
    fn private_key_data_input<PATH>(key: &SK, path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item = T>;
    fn public_key_data_input<PATH>(key: &PK, path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item = T>;
}

impl IChildKeyDerivationData<u32, [u8; 32], [u8; 33]> for ECDSAKey {
    fn private_key_data_input<PATH>(key: &[u8; 32], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=u32> {
        let index = path.index_at_position(position);
        let buf = &mut [0u8; 37];
        if index & BIP32_HARD != 0 {
            buf[1..33].copy_from_slice(key);
        } else {
            buf[..33].copy_from_slice(&secp256k1_point_from_bytes(key));
        }
        buf[33..37].copy_from_slice(index.to_be_bytes().as_slice());
        buf.to_vec()
    }

    fn public_key_data_input<PATH>(key: &[u8; 33], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=u32> {
        let index = path.index_at_position(position);
        if index & BIP32_HARD != 0 {
            panic!("can't derive private child key from public parent key");
        }
        let writer = &mut [0u8; 37];
        writer[..33].copy_from_slice(key);
        writer[33..].copy_from_slice(&index.to_be_bytes());
        writer.to_vec()
    }
}

impl IChildKeyDerivationData<[u8; 32], [u8; 32], [u8; 33]> for ECDSAKey {
    fn private_key_data_input<PATH>(key: &[u8; 32], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=[u8; 32]> {
        let index = path.index_at_position(position);
        let index = UInt256(index);
        let is_hardened = path.hardened_at_position(position);
        let i_is_31_bits = index.is_31_bits();
        let mut writer = Vec::<u8>::new();
        if is_hardened {
            0u8.enc(&mut writer);
            writer.extend_from_slice(key);
        } else {
            writer.extend_from_slice(&secp256k1_point_from_bytes(key));
        };
        if i_is_31_bits {
            let mut small_i = index.u32_le();
            if is_hardened {
                small_i |= BIP32_HARD;
            }
            small_i.swap_bytes().enc(&mut writer);
        } else {
            index.enc(&mut writer);
        };
        writer
    }

    fn public_key_data_input<PATH>(key: &[u8; 33], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=[u8; 32]> {
        let index = path.index_at_position(position);
        let index = UInt256(index);
        let is_hardened = path.hardened_at_position(position);
        if is_hardened {
            panic!("can't derive private child key from public parent key");
        }
        let mut writer = key.to_vec();
        if index.is_31_bits() {
            writer.extend_from_slice(&index.u32_le().to_be_bytes());
        } else {
            writer.extend_from_slice(index.as_bytes());
        };
        writer
    }
}

impl IChildKeyDerivationData<u32, SigningKey, [u8; 32]> for ED25519Key {
    fn private_key_data_input<PATH>(key: &SigningKey, path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=u32> {
        let mut index = path.index_at_position(position);
        // it's always hardened
        index |= BIP32_HARD;
        let writer = &mut [0u8; 37];
        writer[1..33].copy_from_slice(&key.to_bytes());
        writer[33..37].copy_from_slice(&index.to_be_bytes());
        writer.to_vec()
    }

    fn public_key_data_input<PATH>(key: &[u8; 32], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=u32> {
        let index = path.index_at_position(position);
        if index & BIP32_HARD != 0 {
            panic!("can't derive private child key from public parent key");
        }
        let writer = &mut [0u8; 36];
        writer[..32].copy_from_slice(key);
        writer[32..].copy_from_slice(&index.to_be_bytes());
        writer.to_vec()
    }
}

impl IChildKeyDerivationData<[u8; 32], SigningKey, [u8; 32]> for ED25519Key {
    fn private_key_data_input<PATH>(key: &SigningKey, path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=[u8; 32]> {
        let index = path.index_at_position(position);
        let index = UInt256(index);
        let is_hardened = path.hardened_at_position(position);

        let i_is_31_bits = index.is_31_bits();
        let mut writer = Vec::<u8>::new();
        if is_hardened {
            0u8.enc(&mut writer);
            writer.extend_from_slice(&key.to_bytes());
        } else {
            panic!("For ED25519 only hardened derivation is supported");
        };
        if i_is_31_bits {
            let mut small_i = index.u32_le();
            if is_hardened {
                small_i |= BIP32_HARD;
            }
            small_i.swap_bytes().enc(&mut writer);
        } else {
            index.enc(&mut writer);
        };
        writer
    }

    fn public_key_data_input<PATH>(key: &[u8; 32], path: &PATH, position: usize) -> Vec<u8> where PATH: IIndexPath<Item=[u8; 32]> {
        let index = path.index_at_position(position);
        let index = UInt256(index);
        let is_hardened = path.hardened_at_position(position);
        if is_hardened {
            panic!("can't derive private child key from public parent key");
        }
        let mut writer = key.to_vec();
        if index.is_31_bits() {
            writer.extend_from_slice(&index.u32_le().to_be_bytes());
        } else {
            writer.extend_from_slice(index.as_bytes());
        };
        writer
    }
}

pub trait SignKey: Sized {
    // type Inner;
}

impl SignKey for [u8; 32] { /*type Inner = UInt256;*/ }
impl SignKey for SigningKey { /*type Inner = SigningKey;*/ }

pub trait IChildKeyDerivation<T, SK, PK> where SK: SignKey + ?Sized {
    fn derive_child_private_key<PATH>(key: &mut SK, chaincode: &mut [u8; 32], path: &PATH, position: usize) where PATH: IIndexPath<Item = T>;
    fn derive_child_public_key<PATH>(key: &mut PK, chaincode: &mut [u8; 32], path: &PATH, position: usize) where PATH: IIndexPath<Item = T>;
}

pub fn secp256k1_point_from_bytes(data: &[u8]) -> [u8; 33] {
    let sec = secp256k1::SecretKey::from_slice(data).unwrap();
    let s = secp256k1::Secp256k1::new();
    let pub_key = secp256k1::PublicKey::from_secret_key(&s, &sec);
    pub_key.serialize()
}


impl<T> IChildKeyDerivation<T, [u8; 32], [u8; 33]> for ECDSAKey where Self: IChildKeyDerivationData<T, [u8; 32], [u8; 33]> {
    fn derive_child_private_key<PATH>(key: &mut [u8; 32], chaincode: &mut [u8; 32], path: &PATH, position: usize)
        where PATH: IIndexPath<Item=T> {
        let i = UInt512::hmac(chaincode.as_ref(), Self::private_key_data_input(key, path, position).as_ref());
        let mut sec_key = secp256k1::SecretKey::from_slice(key).expect("invalid private key");
        let tweak = Scalar::from_be_bytes(clone_into_array(&i.0[..32])).expect("invalid tweak");
        sec_key = sec_key.add_tweak(&tweak).expect("failed to add tweak");
        key.copy_from_slice(&sec_key.secret_bytes());
        chaincode.copy_from_slice(&i.0[32..]);
    }

    fn derive_child_public_key<PATH>(key: &mut [u8; 33], chaincode: &mut [u8; 32], path: &PATH, position: usize)
        where PATH: IIndexPath<Item=T> {
        let i = UInt512::hmac(chaincode.as_ref(), Self::public_key_data_input(key, path, position).as_ref());
        let s = secp256k1::Secp256k1::new();
        let mut pub_key = secp256k1::PublicKey::from_slice(key).expect("invalid public key");
        let tweak = Scalar::from_be_bytes(clone_into_array(&i.0[..32])).expect("invalid tweak");
        pub_key = pub_key.add_exp_tweak(&s, &tweak).expect("failed to add exp tweak");
        chaincode.copy_from_slice(&i.0[32..]);
        key.copy_from_slice(pub_key.serialize().as_slice())
    }
}

impl<T> IChildKeyDerivation<T, SigningKey, [u8; 32]> for ED25519Key where Self: IChildKeyDerivationData<T, SigningKey, [u8; 32]> {
    fn derive_child_private_key<PATH>(key: &mut SigningKey, chaincode: &mut [u8; 32], path: &PATH, position: usize)
        where PATH: IIndexPath<Item=T> {
        let i = UInt512::hmac(chaincode.as_ref(), Self::private_key_data_input(key, path, position).as_ref());
        let scalar: [u8; 32] = i.0[..32].try_into().unwrap();
        let signing_key = SigningKey::from(&scalar);
        key.clone_from(&signing_key);
        chaincode.copy_from_slice(&i.0[32..]);
    }

    fn derive_child_public_key<PATH>(key: &mut [u8; 32], chaincode: &mut [u8; 32], path: &PATH, position: usize)
        where PATH: IIndexPath<Item=T> {
        let i = UInt512::hmac(chaincode.as_ref(), Self::public_key_data_input(key, path, position).as_ref());
        let scalar: [u8; 32] = i.0[..32].try_into().unwrap();
        match VerifyingKey::from_bytes(&scalar) {
            Ok(pub_key) => {
                key.copy_from_slice(pub_key.as_bytes());
                chaincode.copy_from_slice(&i.0[32..]);
            },
            Err(err) => panic!("{}", err)
        }
    }
}

// #[test]
// pub fn test_identity_key() {
//     // get_identities_for_wallets -> wallet_id: e1049d4399c689f4: index: 0: key: ECDSA(ECDSAKey { seckey: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], pubkey: [2, 63, 137, 159, 254, 152, 58, 243, 60, 149, 56, 138, 170, 139, 57, 131, 111, 6, 201, 51, 226, 108, 213, 101, 243, 23, 230, 50, 134, 44, 223, 38, 130], compressed: true, chaincode: [3, 209, 66, 1, 182, 0, 244, 102, 103, 196, 92, 56, 17, 157, 182, 98, 231, 68, 6, 220, 168, 235, 114, 138, 112, 27, 246, 174, 167, 252, 162, 168], fingerprint: 627235130, is_extended: true })
//     let pub_key: [u8; 33] = [2, 63, 137, 159, 254, 152, 58, 243, 60, 149, 56, 138, 170, 139, 57, 131, 111, 6, 201, 51, 226, 108, 213, 101, 243, 23, 230, 50, 134, 44, 223, 38, 130];
//     let key = ECDSAKey {
//         seckey: [0; 32],
//         pubkey: pub_key.to_vec(),
//         compressed: true,
//         chaincode: [3, 209, 66, 1, 182, 0, 244, 102, 103, 196, 92, 56, 17, 157, 182, 98, 231, 68, 6, 220, 168, 235, 114, 138, 112, 27, 246, 174, 167, 252, 162, 168],
//         fingerprint: 627235130,
//         is_extended: true,
//     };
//
//
//     let index_path = IndexPath::new(vec![0 | BIP32_HARD, 0 | BIP32_HARD]);
//
//     let public_key = key.public_key_from_extended_public_key_data_at_index_path(&index_path);
//     assert!(public_key.is_ok());
// }
//
