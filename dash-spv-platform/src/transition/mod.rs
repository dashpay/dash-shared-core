use dashcore::blockdata::transaction::{OutPoint, Transaction, txin::TxIn, txout::TxOut};
use dashcore::ephemerealdata::instant_lock::InstantLock;
use dashcore::hashes::Hash;
#[cfg(test)]
use dashcore::hashes::hex::FromHex;
use dashcore::hash_types::Txid;
#[cfg(test)]
use dashcore::secp256k1::hashes::hex::DisplayHex;
use dashcore::signer;
use dashcore::signer::double_sha;
use dashcore::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::transaction::special_transaction::TransactionPayload;

#[cfg(test)]
use dpp::{
    identity::{accessors::IdentityGettersV0, Identity, identity_public_key::accessors::v0::IdentityPublicKeyGettersV0, KeyType, v0::IdentityV0},
    native_bls::NativeBlsModule,
    serialization::Signable,
    state_transition::{
        StateTransition, StateTransitionLike,
        state_transitions::identity::identity_create_transition::{IdentityCreateTransition, methods::IdentityCreateTransitionMethodsV0}
    }
};


use dpp::identity::IdentityPublicKey;
use dpp::identity::signer::Signer;
use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
use dpp::identity::state_transition::asset_lock_proof::chain::ChainAssetLockProof;
use dpp::ProtocolError;
use platform_value::BinaryData;

#[ferment_macro::export]
pub fn instant_proof(
    output_index: u32,
    instant_lock: InstantLock,
    tx_version: u16, lock_time: u32, input: Vec<TxIn>, output: Vec<TxOut>,
    asset_lock_payload_version: u8, credit_outputs: Vec<TxOut>
) -> AssetLockProof {
    AssetLockProof::Instant(InstantAssetLockProof {
        instant_lock,
        transaction: Transaction {
            version: tx_version,
            lock_time,
            input,
            output,
            special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
                version: asset_lock_payload_version,
                credit_outputs,
            })),
        },
        output_index,
    })
}

#[ferment_macro::export]
pub fn chain_proof(core_chain_locked_height: u32, txid: [u8; 32], vout: u32) -> AssetLockProof {
    AssetLockProof::Chain(ChainAssetLockProof {
        core_chain_locked_height,
        out_point: OutPoint {
            txid: Txid::from_byte_array(txid),
            vout,
        },
    })
}

// #[test]
// fn test_identity_funding_transaction_unique_id() {
//     use base64::{alphabet, Engine, engine::{GeneralPurpose, GeneralPurposeConfig}};
//     use dashcore::bls_sig_utils::BLSSignature;
//     use dashcore::consensus::Decodable;
//     use dashcore::hash_types::CycleHash;
//     use dashcore::hashes::{sha256d, Hash};
//     use dashcore::hashes::hex::FromHex;
//     use dashcore::secp256k1::{ThirtyTwoByteHash, hashes::hex::DisplayHex};
//     use dashcore::{signer, Txid};
//     use dash_spv_crypto::keys::{ECDSAKey, IKey};
//     use dpp::dashcore::InstantLock;
//     use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
//     use dpp::identity::KeyType;
//     use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
//     use dpp::serialization::{PlatformSerializable, Signable};
//     use dpp::state_transition::state_transitions::identity::identity_create_transition::IdentityCreateTransition;
//     use dpp::state_transition::state_transitions::identity::identity_create_transition::v0::IdentityCreateTransitionV0;
//     use dpp::state_transition::state_transitions::identity::public_key_in_creation::IdentityPublicKeyInCreation;
//     use dpp::state_transition::state_transitions::identity::public_key_in_creation::v0::IdentityPublicKeyInCreationV0;
//     use dpp::state_transition::StateTransition;
//     use platform_value::{BinaryData, Identifier};
//     use platform_value::string_encoding::Encoding;
//     use dash_spv_crypto::crypto::byte_util::Reversed;
//
//     let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
//     let mut signature = [0u8; 96];
//     signature[0] = 1;
//
//     let bls_signature = BLSSignature::from(signature);
//
//     let tx_data = b"0300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000";
//     let mut transaction_data = tx_data.as_slice();
//     // let funding_tx = Transaction::de(transaction_data);
//     // let hash = funding_tx.base.tx_hash().unwrap();
//     let txid = Txid::from_slice(&hash).unwrap();
//     let is_lock = InstantLock {
//         version: 0,
//         inputs: vec![],
//         txid,
//         cyclehash: CycleHash::from_raw_hash(sha256d::Hash::from_slice(&[0u8; 32]).unwrap()),
//         signature: bls_signature,
//     };
//     assert_eq!(is_lock.request_id().unwrap().to_byte_array().to_lower_hex_string(), <[u8; 32]>::from_hex("7bab86a676ac6cd3ab0b8180f37121a36d8ae6fecea59e7c4e7783ce9cb84696").unwrap().reversed().to_lower_hex_string());
//
//     let funding_tx_locked_outpoint = funding_tx.locked_outpoint().unwrap();
//     let transaction = Transaction::consensus_decode(&mut transaction_data).unwrap();
//     assert_eq!(txid, transaction.txid(), "ddd");
//     let transaction_locked_outpoint = transaction.locked_outpoint().unwrap();
//     let out_index = transaction_locked_outpoint.vout;
//     let instant_asset_lock_proof = InstantAssetLockProof::new(is_lock, transaction, out_index);
//     let identifier = instant_asset_lock_proof.create_identifier().unwrap();
//     println!("Identifier: {}", identifier);
//     let asset_lock_proof = AssetLockProof::Instant(instant_asset_lock_proof);
//
//     println!("funding_tx_locked_outpoint tx_id: {}", funding_tx_locked_outpoint.txid.to_hex());
//     println!("funding_tx_locked_outpoint vout: {}", funding_tx_locked_outpoint.vout);
//     println!("transaction_locked_outpoint tx_id: {}", transaction_locked_outpoint.txid.to_hex());
//     println!("transaction_locked_outpoint vout: {}", transaction_locked_outpoint.vout);
//     let credit_burn_identity_id = funding_tx.credit_burn_identity_identifier();
//
//
//
//     assert_eq!(credit_burn_identity_id.to_lower_hex_string(), "ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string(), "Credit Burn Identity Identifier is incorrect");
//     // assert_eq!(credit_burn_identity_id.to_hex(), transaction.credit_burn_identity_identifier().to_hex(), "Credit Burn Identity Identifier is incorrect");
//     let credit_burn_public_key_hash = funding_tx.credit_burn_public_key_hash().unwrap();
//     assert_eq!(credit_burn_public_key_hash.to_lower_hex_string(), "14ec6c36e6c39a9181f3a261a08a5171425ac5e2".to_string(), "Credit Burn Identity Public Key Hash is incorrect");
//     // assert_eq!(credit_burn_public_key_hash.to_hex(), transaction.credit_burn_public_key_hash().unwrap().to_hex(), "Credit Burn Identity Public Key Hash is incorrect");
//     let identity_identifier =  funding_tx.credit_burn_identity_identifier_base58();
//     assert_eq!(identity_identifier, "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
//     // assert_eq!(transaction.credit_burn_identity_identifier_base58(), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
//     let public_key = ECDSAKey::key_with_public_key_data(&base64_engine.decode("AsPvyyh6pkxss/Fespa7HCJIY8IA6ElAf6VKuqVcnPze").unwrap()).unwrap();
//     let private_key_data = b"fdbca0cd2be4375f04fcaee5a61c5d170a2a46b1c0c7531f58c430734a668f32";
//     let private_key = ECDSAKey::key_with_secret_data(private_key_data.as_slice(), true).unwrap();
//     let public_key_data = private_key.public_key_data();
//     assert_eq!(public_key_data.to_lower_hex_string(), "02c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde".to_string(), "Public Key Data is incorrect");
//     assert_eq!(public_key.hash160(), credit_burn_public_key_hash, "The private key doesn't match the funding transaction");
//     let mut transition = StateTransition::IdentityCreate(IdentityCreateTransition::V0(IdentityCreateTransitionV0 {
//         public_keys: vec![IdentityPublicKeyInCreation::V0(IdentityPublicKeyInCreationV0 {
//             id: 1,
//             key_type: KeyType::ECDSA_SECP256K1,
//             purpose: Purpose::AUTHENTICATION,
//             security_level: SecurityLevel::MASTER,
//             contract_bounds: None,
//             read_only: false,
//             data: BinaryData(public_key_data),
//             signature: Default::default(),
//         })],
//         asset_lock_proof,
//         user_fee_increase: 0,
//         signature: Default::default(),
//         // self.blockchainIdentityUniqueId = [dsutxo_data(creditFundingTransaction.lockedOutpoint) SHA256_2];
//
//         identity_id: Identifier::from(funding_tx.credit_burn_identity_identifier()),
//     }));
//     // let identity_public_key = IdentityPublicKey::V0()
//
//     let data = transition.signable_bytes().unwrap();
//     println!("sign_id: {}", data.to_lower_hex_string());
//     let signature = signer::sign(&data, private_key_data.as_slice()).unwrap();
//     transition.set_signature(signature.to_vec().into());
//
//     assert_eq!(transition.owner_id().to_string(Encoding::Base58), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string());
//     // 7c4855e4230f5705498b2209bb3bebbe337684af58b9b21bb235bf8a31138951
//     println!("Transition Owner ID: {}", transition.owner_id());
//     println!("Transition Signature: {}", transition.signature().to_vec().to_lower_hex_string());
//     println!("Transition Serialized to bytes: {}", transition.serialize_to_bytes().unwrap().to_lower_hex_string());
//     let hashed = sha256d::Hash::hash(&transition.serialize_to_bytes().unwrap()).into_32();
//     println!("Transition SHA256-2: {}", hashed.to_lower_hex_string());
//
//     let result = "0001000100000000004104c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde9ad99fb575a4dc3eeacb835c9b607e54a436aef621cfc09797984bcb325c8e3c0000a20100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01ffffffffffffffff0000000000000000ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string();
//     let result = transition.serialize_to_bytes().unwrap().to_lower_hex_string();
//     let etalon = "01000000a4647479706502697369676e617475726558411fe06d3cd2671ec7f6653eb45f40ab4bce27f42a46893997042f87b344913aee3b794aeaf632b4887516a7765b2329569d45176fe7e090defc1a077889a93fdf076a7075626c69634b65797381a6626964016464617461582102c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde64747970650067707572706f73650068726561644f6e6c79f46d73656375726974794c6576656c006e61737365744c6f636b50726f6f66a46474797065006b696e7374616e744c6f636b58810025847e1e9c2ef692d21bc23a6c0faf8834d64704e5e0186427d3444bc75c1ba50100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b6f7574707574496e646578006b7472616e73616374696f6e5901950300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000".to_string();
//
//     // println!("transition_serialized: {}", transition_serialized.to_hex());
//     // [blockchainIdentityRegistrationTransition signWithKey:privateKey atIndex:UINT32_MAX fromIdentity:nil];
//     // let transition_signed = private_key.sign(&transition_serialized);
//     // println!("transition_signed: {}", transition_signed.to_hex());
// }

// pub async fn identity_register_using_public_key_at_index(&self, public_key: IdentityPublicKey, index: u32, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
//     println!("transition identity_register_using_public_key_at_index: {:?} -- {} -- {:?} -- {:?}", public_key, index, proof, private_key);
//     let public_keys = BTreeMap::from_iter([(index, public_key)]);
//     let (identity, transition) = self.identities.create_identity_create_transition_using_public_keys(public_keys, proof)
//         .map_err(Error::from)?;
//     println!("transition register created: {:?} -- {:?}", identity, transition);
//     let signature = self.create_transition_signature(&transition, private_key)?;
//     self.sign_and_publish_transition(StateTransition::IdentityCreate(transition), signature.to_vec()).await
// }

#[derive(Debug)]
pub struct TestSigner {
    pub private_key: Vec<u8>
}
impl Signer for TestSigner {
    fn sign(&self, _identity_public_key: &IdentityPublicKey, data: &[u8]) -> Result<BinaryData, ProtocolError> {
        // signer::sign_hash()
        let hash = double_sha(data);
        // let hash = sha256d::Hash::hash(data).into_inner();;
        signer::sign_hash(&hash, &self.private_key).map_err(ProtocolError::from).map(|d| BinaryData::from(d.to_vec()))
    }

    fn can_sign_with(&self, _identity_public_key: &IdentityPublicKey) -> bool {
        true
    }
}

#[cfg(test)]
fn identity_fixture() -> Identity {
    use std::collections::BTreeMap;
    use platform_value::{Identifier, IdentifierBytes32};
    Identity::V0(IdentityV0 {
        id: Identifier(IdentifierBytes32([98, 133, 105, 167, 166, 167, 34, 219, 173, 197, 92, 195, 127, 176, 26, 249, 89, 164, 21, 80, 121, 53, 90, 104, 119, 80, 167, 119, 212, 192, 32, 227])),
        public_keys: BTreeMap::from_iter([(0, identity_public_key_fixture())]),
        balance: 0,
        revision: 0,
    })
}
#[cfg(test)]
fn identity_public_key_fixture() -> IdentityPublicKey {
    use dpp::identity::identity_public_key::{Purpose, SecurityLevel, v0::IdentityPublicKeyV0};
    use platform_value::string_encoding::Encoding;
    let data = BinaryData::from_string("026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b", Encoding::Hex)
        .expect("Failed to create public key data");
    let public_key =  IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: 0,
        purpose: Purpose::AUTHENTICATION,
        security_level: SecurityLevel::MASTER,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: false,
        data,
        disabled_at: None
    });
    public_key
}
#[cfg(test)]
fn asset_lock_transaction_fixture() -> Transaction {
    use dashcore::consensus::deserialize;
    let transaction_bytes = Vec::from_hex("03000800018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be010000006a4730440220765c83e5e908448ab2117a4abb806d21a3786d9642fc1883405c34367c1e5f3702207a0d1eae897e842b45632e57d02647ae193e8c7a247674399bc24d2d80799a88012102e25c6bbcbb1aa0a0c42283ded2d44e5c75551318a3c01d65906ac97aae1603e8ffffffff0240420f0000000000026a00c90ced02000000001976a914e97fe30aafd3666e70493b99cc35c0371d26654088ac0000000024010140420f00000000001976a91467575fc9d201b5ff36b5d8405497f1d961a56dbf88ac").unwrap();
    let transaction: Transaction = deserialize(transaction_bytes.as_slice()).unwrap();
    transaction
}
#[cfg(test)]
fn instant_lock_fixture() -> InstantLock {
    use dashcore::consensus::deserialize;
    let is_lock_bytes = Vec::from_hex("01018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be01000000b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020766a93587154beb1624054fbef93d73a2403295e459e6d85c3245021487e02000094325d06a52a1f3cfaa74de4ca28f9c5b16c5ee2b472e50219cc78a111cf1c987c1d861e0a6018fdaf41960caf6ba349126e99446f00edc19856b9dab8fa15e12ae42c67d4f958a8e5fbc8af224fe4cc2c85d2e186296d7433e2fec0112a862a").unwrap();
    let is_lock: InstantLock = deserialize(is_lock_bytes.as_slice()).unwrap();
    is_lock
}
#[cfg(test)]
fn instant_proof_fixture() -> AssetLockProof {
    let transaction = asset_lock_transaction_fixture();
    let is_lock = instant_lock_fixture();
    let instant_proof = AssetLockProof::Instant(InstantAssetLockProof::new(is_lock, transaction, 0));
    instant_proof
}
#[cfg(test)]
fn chain_proof_fixture() -> AssetLockProof {
    let core_chain_locked_height = 1199074;
    let tx_id = <[u8; 32]>::from_hex("762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1").expect("???");
    let out_point = OutPoint { txid: Txid::from_slice(&tx_id).unwrap(), vout: 0 };
    let chain_proof = AssetLockProof::Chain(ChainAssetLockProof { core_chain_locked_height, out_point });
    chain_proof
}
#[test]
fn test_identity_registration_transition() {
    use platform_version::version::PlatformVersion;
    let seckey: [u8; 32] = [255, 17, 59, 229, 243, 12, 106, 175, 152, 150, 39, 18, 157, 168, 179, 198, 146, 46, 53, 0, 228, 201, 234, 212, 75, 51, 161, 237, 102, 173, 35, 211];
    let test_signer = TestSigner { private_key: seckey.to_vec() };
    let identity = identity_fixture();
    let transaction = asset_lock_transaction_fixture();
    let is_lock = instant_lock_fixture();
    let instant_proof = instant_proof_fixture();
    let chain_proof = chain_proof_fixture();

    println!("transaction: {:?}", transaction);
    println!("is_lock: {:?}", is_lock);
    println!("instant_proof: {:?}", instant_proof);
    println!("chain_proof: {:?}", chain_proof);

    // let mut transition = facade.create_identity_create_transition(&identity, chain_proof).expect("Failed to create identity create transition");
    let mut transition: StateTransition =
        IdentityCreateTransition::try_from_identity_with_signer(
            &identity,
            chain_proof,
            seckey.as_slice(),
            &test_signer,
            &NativeBlsModule,
            0,
            PlatformVersion::latest(),
        )
            .expect("expected an identity create transition");
    // transition.sign(&public_key, &seckey, &NativeBlsModule);
    // println!("transition: {:?}", transition);
    let data = transition.signable_bytes().expect("Failed to get signable bytes");
    println!("signable_bytes: {}", data.to_lower_hex_string());
    let public_key = identity.public_keys().first_key_value().unwrap().1;
    println!("public_key_data: {}", public_key.data().0.to_lower_hex_string());
    // let signature = dashcore::signer::sign(&data, &seckey).expect("Failed to sign transition");
    // transition.set_signature(signature.to_vec().into());
    // println!("signature: {}", signature.to_hex());
    // let transition = IdentityCreateTransition::V0(transition_v0);
    let result = transition.sign_by_private_key(&seckey, KeyType::ECDSA_SECP256K1, &NativeBlsModule);
    assert!(result.is_ok(), "Failed to sign transition");
    // let result = transition.sign(&public_key, &seckey, &NativeBlsModule);
    // println!("transition after signing: {:?}", transition);

    // let data = transition.signable_bytes()?;
    let verified = signer::verify_data_signature(&data, transition.signature().as_slice(), public_key.data().as_slice());
    // let result = signer::verify_data_signature(&data, signature.as_slice(), public_key_data.as_slice());

    assert!(verified.is_ok(), "Failed to verify signature");

    // transition identity_register_using_public_key_at_index: V0(IdentityPublicKeyV0 { id: 0, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), disabled_at: None }) -- 0 -- Chain(ChainAssetLockProof { core_chain_locked_height: 1199074, out_point: OutPoint { txid: 0x762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1, vout: 0 } }) -- ECDSA(ECDSAKey { seckey: [255, 17, 59, 229, 243, 12, 106, 175, 152, 150, 39, 18, 157, 168, 179, 198, 146, 46, 53, 0, 228, 201, 234, 212, 75, 51, 161, 237, 102, 173, 35, 211], pubkey: [], compressed: true, chaincode: [168, 25, 122, 213, 160, 35, 81, 86, 25, 234, 90, 84, 126, 18, 143, 232, 196, 32, 187, 188, 210, 25, 58, 133, 173, 65, 149, 233, 107, 90, 189, 26], fingerprint: 3103239245, is_extended: true })
    // transition register created: V0(IdentityV0 { id: Identifier(IdentifierBytes32([90, 31, 92, 134, 2, 135, 134, 141, 135, 186, 27, 238, 194, 146, 89, 30, 71, 113, 112, 7, 56, 174, 248, 87, 190, 111, 179, 81, 113, 41, 147, 99])), public_keys: {0: V0(IdentityPublicKeyV0 { id: 0, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), disabled_at: None })}, balance: 0, revision: 0 }) -- V0(IdentityCreateTransitionV0 { public_keys: [V0(IdentityPublicKeyInCreationV0 { id: 0, key_type: ECDSA_SECP256K1, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), signature: BinaryData(0x) })], asset_lock_proof: Chain(ChainAssetLockProof { core_chain_locked_height: 1199074, out_point: OutPoint { txid: 0x762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1, vout: 0 } }), user_fee_increase: 0, signature: BinaryData(0x), identity_id: Identifier(IdentifierBytes32([90, 31, 92, 134, 2, 135, 134, 141, 135, 186, 27, 238, 194, 146, 89, 30, 71, 113, 112, 7, 56, 174, 248, 87, 190, 111, 179, 81, 113, 41, 147, 99])) })
    // transition signable bytes: 00010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc00124be220b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000
    // transition signature: 1fa237a83b4653752935da780bc2730fb37df5e250b4abacce302cf94ca50cd1ba7ebd4e339d532ce4fb9c8e01d91da9516d1cd96cf45f1193c0cfc24fa250a590
}

#[test]
fn verify_chain_proof_signed_data() {
    let chain_proof_signable_bytes = Vec::from_hex("0300010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc7fffffff20b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000")
        .expect("Hex data");
    // let chain_proof_signable_bytes = Vec::from_hex("0300010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc00124be220762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb10000")
    //     .expect("Hex data");
    let signature = Vec::from_hex("207abce1bcd8bba4ba32a65478144837e4dad7fdb245d69de4645df5f0f298d11b608e3a2bdaea30d12d9d9449ee93e5ba5dc59fb36a80217fe0fb670fcaf5b1f4")
        .expect("Hex data");
    let identity = identity_fixture();
    let public_key = identity.public_keys().first_key_value().unwrap().1;
    let result = signer::verify_data_signature(&chain_proof_signable_bytes, signature.as_slice(), public_key.data().as_slice());
    assert!(result.is_ok(), "Failed to verify signature");
}

#[test]
fn verify_instant_proof_signed_data() {
    let chain_proof_signable_bytes = Vec::from_hex("00010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b00a20000b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef03000800018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be010000006a4730440220765c83e5e908448ab2117a4abb806d21a3786d9642fc1883405c34367c1e5f3702207a0d1eae897e842b45632e57d02647ae193e8c7a247674399bc24d2d80799a88012102e25c6bbcbb1aa0a0c42283ded2d44e5c75551318a3c01d65906ac97aae1603e8ffffffff0240420f0000000000026a00c90ced02000000001976a914e97fe30aafd3666e70493b99cc35c0371d26654088ac0000000024010140420f00000000001976a91467575fc9d201b5ff36b5d8405497f1d961a56dbf88ac0000")
        .expect("Hex data");
    let signature = Vec::from_hex("1f4ee8736f228e9d6ecb4c1ee204c3fbd3310caf7bb08416bc784adaa81f1b9e7848bee1a8f72bc0cbb8da0e38ecef14033999b4ab861d865890e65fb50599e89c")
        .expect("Hex data");
    let identity = identity_fixture();
    let public_key = identity.public_keys().first_key_value().unwrap().1;
    let result = signer::verify_data_signature(&chain_proof_signable_bytes, signature.as_slice(), public_key.data().as_slice());
    assert!(result.is_ok(), "Failed to verify signature");
}

// #[test]
// fn test_identity_funding_transaction_unique_id() {
//     use base64::{alphabet, Engine, engine::{GeneralPurpose, GeneralPurposeConfig}};
//     use dashcore::bls_sig_utils::BLSSignature;
//     use dashcore::consensus::Decodable;
//     use dashcore::hash_types::CycleHash;
//     use dashcore::hashes::{sha256d, Hash};
//     use dashcore::secp256k1::ThirtyTwoByteHash;
//     use dashcore::{signer, Txid};
//     use dash_spv_crypto::hashes::hex::{FromHex, ToHex};
//     use dash_spv_crypto::keys::{ECDSAKey, IKey};
//     use dash_spv_crypto::tx::credit_funding::{CreditFunding, CreditFundingTransaction};
//     use dpp::dashcore::InstantLock;
//     use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
//     use dpp::identity::KeyType;
//     use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
//     use dpp::serialization::{PlatformSerializable, Signable};
//     use dpp::state_transition::identity::identity_create_transition::IdentityCreateTransition;
//     use dpp::state_transition::identity::identity_create_transition::v0::IdentityCreateTransitionV0;
//     use dpp::state_transition::identity::public_key_in_creation::IdentityPublicKeyInCreation;
//     use dpp::state_transition::identity::public_key_in_creation::v0::IdentityPublicKeyInCreationV0;
//     use dpp::state_transition::StateTransition;
//     use platform_value::{BinaryData, Identifier};
//     use platform_value::string_encoding::Encoding;
//     use dash_spv_crypto::crypto::byte_util::Reversed;
//
//     let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
//     let mut signature = [0u8; 96];
//     signature[0] = 1;
//
//     let bls_signature = BLSSignature::from(signature);
//
//     let tx_data = b"0300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000";
//     let mut transaction_data = tx_data.as_slice();
//     let funding_tx = CreditFundingTransaction::from(transaction_data);
//     let hash = funding_tx.base.tx_hash().unwrap();
//     let txid = Txid::from_slice(&hash).unwrap();
//     let is_lock = InstantLock {
//         version: 0,
//         inputs: vec![],
//         txid,
//         cyclehash: CycleHash::from_raw_hash(sha256d::Hash::from_slice(&[0u8; 32]).unwrap()),
//         signature: bls_signature,
//     };
//     assert_eq!(is_lock.request_id().unwrap().to_hex(), <[u8; 32]>::from_hex("7bab86a676ac6cd3ab0b8180f37121a36d8ae6fecea59e7c4e7783ce9cb84696").unwrap().reversed().0.to_hex());
//
//     let funding_tx_locked_outpoint = funding_tx.locked_outpoint().unwrap();
//     let transaction = dashcore::blockdata::transaction::Transaction::consensus_decode(&mut transaction_data).unwrap();
//     assert_eq!(txid, transaction.txid(), "ddd");
//     let transaction_locked_outpoint = transaction.locked_outpoint().unwrap();
//     let out_index = transaction_locked_outpoint.vout;
//     let instant_asset_lock_proof = InstantAssetLockProof::new(is_lock, transaction, out_index);
//     let identifier = instant_asset_lock_proof.create_identifier().unwrap();
//     println!("Identifier: {}", identifier);
//     let asset_lock_proof = AssetLockProof::Instant(instant_asset_lock_proof);
//
//     println!("funding_tx_locked_outpoint tx_id: {}", funding_tx_locked_outpoint.txid.to_hex());
//     println!("funding_tx_locked_outpoint vout: {}", funding_tx_locked_outpoint.vout);
//     println!("transaction_locked_outpoint tx_id: {}", transaction_locked_outpoint.txid.to_hex());
//     println!("transaction_locked_outpoint vout: {}", transaction_locked_outpoint.vout);
//     let credit_burn_identity_id = funding_tx.credit_burn_identity_identifier();
//
//
//
//     assert_eq!(credit_burn_identity_id.to_hex(), "ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string(), "Credit Burn Identity Identifier is incorrect");
//     // assert_eq!(credit_burn_identity_id.to_hex(), transaction.credit_burn_identity_identifier().to_hex(), "Credit Burn Identity Identifier is incorrect");
//     let credit_burn_public_key_hash = funding_tx.credit_burn_public_key_hash().unwrap();
//     assert_eq!(credit_burn_public_key_hash.to_hex(), "14ec6c36e6c39a9181f3a261a08a5171425ac5e2".to_string(), "Credit Burn Identity Public Key Hash is incorrect");
//     // assert_eq!(credit_burn_public_key_hash.to_hex(), transaction.credit_burn_public_key_hash().unwrap().to_hex(), "Credit Burn Identity Public Key Hash is incorrect");
//     let identity_identifier =  funding_tx.credit_burn_identity_identifier_base58();
//     assert_eq!(identity_identifier, "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
//     // assert_eq!(transaction.credit_burn_identity_identifier_base58(), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
//     let public_key = ECDSAKey::key_with_public_key_data(&base64_engine.decode("AsPvyyh6pkxss/Fespa7HCJIY8IA6ElAf6VKuqVcnPze").unwrap()).unwrap();
//     let private_key_data = b"fdbca0cd2be4375f04fcaee5a61c5d170a2a46b1c0c7531f58c430734a668f32";
//     let private_key = ECDSAKey::key_with_secret_data(private_key_data.as_slice(), true).unwrap();
//     let public_key_data = private_key.public_key_data();
//     assert_eq!(public_key_data.to_hex(), "02c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde".to_string(), "Public Key Data is incorrect");
//     assert_eq!(public_key.hash160(), credit_burn_public_key_hash, "The private key doesn't match the funding transaction");
//     let mut transition = StateTransition::IdentityCreate(IdentityCreateTransition::V0(IdentityCreateTransitionV0 {
//         public_keys: vec![IdentityPublicKeyInCreation::V0(IdentityPublicKeyInCreationV0 {
//             id: 1,
//             key_type: KeyType::ECDSA_SECP256K1,
//             purpose: Purpose::AUTHENTICATION,
//             security_level: SecurityLevel::MASTER,
//             contract_bounds: None,
//             read_only: false,
//             data: BinaryData(public_key_data),
//             signature: Default::default(),
//         })],
//         asset_lock_proof,
//         user_fee_increase: 0,
//         signature: Default::default(),
//         // self.blockchainIdentityUniqueId = [dsutxo_data(creditFundingTransaction.lockedOutpoint) SHA256_2];
//
//         identity_id: Identifier::from(funding_tx.credit_burn_identity_identifier()),
//     }));
//     // let identity_public_key = IdentityPublicKey::V0()
//
//     let data = transition.signable_bytes().unwrap();
//     println!("sign_id: {}", data.to_hex());
//     let signature = signer::sign(&data, private_key_data.as_slice()).unwrap();
//     transition.set_signature(signature.to_vec().into());
//
//     assert_eq!(transition.owner_id().to_string(Encoding::Base58), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string());
//     // 7c4855e4230f5705498b2209bb3bebbe337684af58b9b21bb235bf8a31138951
//     println!("Transition Owner ID: {}", transition.owner_id());
//     println!("Transition Signature: {}", transition.signature().to_vec().to_hex());
//     println!("Transition Serialized to bytes: {}", transition.serialize_to_bytes().unwrap().to_hex());
//     let hashed = sha256d::Hash::hash(&transition.serialize_to_bytes().unwrap()).into_32();
//     println!("Transition SHA256-2: {}", hashed.to_hex());
//
//     let result = "0001000100000000004104c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde9ad99fb575a4dc3eeacb835c9b607e54a436aef621cfc09797984bcb325c8e3c0000a20100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01ffffffffffffffff0000000000000000ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string();
//     let result = transition.serialize_to_bytes().unwrap().to_hex();
//     let etalon = "01000000a4647479706502697369676e617475726558411fe06d3cd2671ec7f6653eb45f40ab4bce27f42a46893997042f87b344913aee3b794aeaf632b4887516a7765b2329569d45176fe7e090defc1a077889a93fdf076a7075626c69634b65797381a6626964016464617461582102c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde64747970650067707572706f73650068726561644f6e6c79f46d73656375726974794c6576656c006e61737365744c6f636b50726f6f66a46474797065006b696e7374616e744c6f636b58810025847e1e9c2ef692d21bc23a6c0faf8834d64704e5e0186427d3444bc75c1ba50100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b6f7574707574496e646578006b7472616e73616374696f6e5901950300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000".to_string();
//
//     // println!("transition_serialized: {}", transition_serialized.to_hex());
//     // [blockchainIdentityRegistrationTransition signWithKey:privateKey atIndex:UINT32_MAX fromIdentity:nil];
//     // let transition_signed = private_key.sign(&transition_serialized);
//     // println!("transition_signed: {}", transition_signed.to_hex());
// }
//
// // pub async fn identity_register_using_public_key_at_index(&self, public_key: IdentityPublicKey, index: u32, proof: AssetLockProof, private_key: OpaqueKey) -> Result<StateTransitionProofResult, Error> {
// //     println!("transition identity_register_using_public_key_at_index: {:?} -- {} -- {:?} -- {:?}", public_key, index, proof, private_key);
// //     let public_keys = BTreeMap::from_iter([(index, public_key)]);
// //     let (identity, transition) = self.identities.create_identity_create_transition_using_public_keys(public_keys, proof)
// //         .map_err(Error::from)?;
// //     println!("transition register created: {:?} -- {:?}", identity, transition);
// //     let signature = self.create_transition_signature(&transition, private_key)?;
// //     self.sign_and_publish_transition(StateTransition::IdentityCreate(transition), signature.to_vec()).await
// // }
//
// #[derive(Debug)]
// pub struct TestSigner {
//     pub private_key: Vec<u8>
// }
// impl Signer for TestSigner {
//     fn sign(&self, identity_public_key: &IdentityPublicKey, data: &[u8]) -> Result<BinaryData, ProtocolError> {
//         // signer::sign_hash()
//         let hash = double_sha(data);
//         // let hash = sha256d::Hash::hash(data).into_inner();;
//         signer::sign_hash(&hash, &self.private_key).map_err(ProtocolError::from).map(|d| BinaryData::from(d.to_vec()))
//     }
//
//     fn can_sign_with(&self, _identity_public_key: &IdentityPublicKey) -> bool {
//         true
//     }
// }
//
// #[cfg(test)]
// fn identity_fixture() -> Identity {
//     Identity::V0(IdentityV0 {
//         id: Identifier(IdentifierBytes32([98, 133, 105, 167, 166, 167, 34, 219, 173, 197, 92, 195, 127, 176, 26, 249, 89, 164, 21, 80, 121, 53, 90, 104, 119, 80, 167, 119, 212, 192, 32, 227])),
//         public_keys: BTreeMap::from_iter([(0, identity_public_key_fixture())]),
//         balance: 0,
//         revision: 0,
//     })
// }
// #[cfg(test)]
// fn identity_public_key_fixture() -> IdentityPublicKey {
//     let data = BinaryData::from_string("026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b", Encoding::Hex)
//         .expect("Failed to create public key data");
//     let public_key =  IdentityPublicKey::V0(IdentityPublicKeyV0 {
//         id: 0,
//         purpose: Purpose::AUTHENTICATION,
//         security_level: SecurityLevel::MASTER,
//         contract_bounds: None,
//         key_type: KeyType::ECDSA_SECP256K1,
//         read_only: false,
//         data,
//         disabled_at: None
//     });
//     public_key
// }
// #[cfg(test)]
// fn asset_lock_transaction_fixture() -> Transaction {
//     let transaction_bytes = Vec::from_hex("03000800018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be010000006a4730440220765c83e5e908448ab2117a4abb806d21a3786d9642fc1883405c34367c1e5f3702207a0d1eae897e842b45632e57d02647ae193e8c7a247674399bc24d2d80799a88012102e25c6bbcbb1aa0a0c42283ded2d44e5c75551318a3c01d65906ac97aae1603e8ffffffff0240420f0000000000026a00c90ced02000000001976a914e97fe30aafd3666e70493b99cc35c0371d26654088ac0000000024010140420f00000000001976a91467575fc9d201b5ff36b5d8405497f1d961a56dbf88ac").unwrap();
//     let transaction: Transaction = deserialize(transaction_bytes.as_slice()).unwrap();
//     transaction
// }
// #[cfg(test)]
// fn instant_lock_fixture() -> InstantLock {
//     let is_lock_bytes = Vec::from_hex("01018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be01000000b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020766a93587154beb1624054fbef93d73a2403295e459e6d85c3245021487e02000094325d06a52a1f3cfaa74de4ca28f9c5b16c5ee2b472e50219cc78a111cf1c987c1d861e0a6018fdaf41960caf6ba349126e99446f00edc19856b9dab8fa15e12ae42c67d4f958a8e5fbc8af224fe4cc2c85d2e186296d7433e2fec0112a862a").unwrap();
//     let is_lock: InstantLock = deserialize(is_lock_bytes.as_slice()).unwrap();
//     is_lock
// }
// #[cfg(test)]
// fn instant_proof_fixture() -> AssetLockProof {
//     let transaction = asset_lock_transaction_fixture();
//     let is_lock = instant_lock_fixture();
//     let instant_proof = AssetLockProof::Instant(InstantAssetLockProof::new(is_lock, transaction, 0));
//     instant_proof
// }
// #[cfg(test)]
// fn chain_proof_fixture() -> AssetLockProof {
//     let core_chain_locked_height = 1199074;
//     let tx_id = <[u8; 32]>::from_hex("762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1").expect("???");
//     let out_point = OutPoint { txid: Txid::from_slice(&tx_id).unwrap(), vout: 0 };
//     let chain_proof = AssetLockProof::Chain(ChainAssetLockProof { core_chain_locked_height, out_point });
//     chain_proof
// }
// #[test]
// fn test_identity_registration_transition() {
//     let facade = IdentityFacade::new(PROTOCOL_VERSION_8);
//     let seckey: [u8; 32] = [255, 17, 59, 229, 243, 12, 106, 175, 152, 150, 39, 18, 157, 168, 179, 198, 146, 46, 53, 0, 228, 201, 234, 212, 75, 51, 161, 237, 102, 173, 35, 211];
//     let test_signer = TestSigner { private_key: seckey.to_vec() };
//     let identity = identity_fixture();
//     let transaction = asset_lock_transaction_fixture();
//     let is_lock = instant_lock_fixture();
//     let instant_proof = instant_proof_fixture();
//     let chain_proof = chain_proof_fixture();
//
//     println!("transaction: {:?}", transaction);
//     println!("is_lock: {:?}", is_lock);
//     println!("instant_proof: {:?}", instant_proof);
//     println!("chain_proof: {:?}", chain_proof);
//
//     // let mut transition = facade.create_identity_create_transition(&identity, chain_proof).expect("Failed to create identity create transition");
//     let mut transition: StateTransition =
//         IdentityCreateTransition::try_from_identity_with_signer(
//             &identity,
//             chain_proof,
//             seckey.as_slice(),
//             &test_signer,
//             &NativeBlsModule,
//             0,
//             PlatformVersion::latest(),
//         )
//             .expect("expected an identity create transition");
//     // transition.sign(&public_key, &seckey, &NativeBlsModule);
//     // println!("transition: {:?}", transition);
//     let data = transition.signable_bytes().expect("Failed to get signable bytes");
//     println!("signable_bytes: {}", data.to_hex());
//     let public_key = identity.public_keys().first_key_value().unwrap().1;
//     println!("public_key_data: {}", public_key.data().0.to_hex());
//     // let signature = dashcore::signer::sign(&data, &seckey).expect("Failed to sign transition");
//     // transition.set_signature(signature.to_vec().into());
//     // println!("signature: {}", signature.to_hex());
//     // let transition = IdentityCreateTransition::V0(transition_v0);
//     let result = transition.sign_by_private_key(&seckey, KeyType::ECDSA_SECP256K1, &NativeBlsModule);
//     assert!(result.is_ok(), "Failed to sign transition");
//     // let result = transition.sign(&public_key, &seckey, &NativeBlsModule);
//     // println!("transition after signing: {:?}", transition);
//
//     // let data = transition.signable_bytes()?;
//     let verified = signer::verify_data_signature(&data, transition.signature().as_slice(), public_key.data().as_slice());
//     // let result = signer::verify_data_signature(&data, signature.as_slice(), public_key_data.as_slice());
//
//     assert!(verified.is_ok(), "Failed to verify signature");
//
//     // transition identity_register_using_public_key_at_index: V0(IdentityPublicKeyV0 { id: 0, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), disabled_at: None }) -- 0 -- Chain(ChainAssetLockProof { core_chain_locked_height: 1199074, out_point: OutPoint { txid: 0x762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1, vout: 0 } }) -- ECDSA(ECDSAKey { seckey: [255, 17, 59, 229, 243, 12, 106, 175, 152, 150, 39, 18, 157, 168, 179, 198, 146, 46, 53, 0, 228, 201, 234, 212, 75, 51, 161, 237, 102, 173, 35, 211], pubkey: [], compressed: true, chaincode: [168, 25, 122, 213, 160, 35, 81, 86, 25, 234, 90, 84, 126, 18, 143, 232, 196, 32, 187, 188, 210, 25, 58, 133, 173, 65, 149, 233, 107, 90, 189, 26], fingerprint: 3103239245, is_extended: true })
//     // transition register created: V0(IdentityV0 { id: Identifier(IdentifierBytes32([90, 31, 92, 134, 2, 135, 134, 141, 135, 186, 27, 238, 194, 146, 89, 30, 71, 113, 112, 7, 56, 174, 248, 87, 190, 111, 179, 81, 113, 41, 147, 99])), public_keys: {0: V0(IdentityPublicKeyV0 { id: 0, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, key_type: ECDSA_SECP256K1, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), disabled_at: None })}, balance: 0, revision: 0 }) -- V0(IdentityCreateTransitionV0 { public_keys: [V0(IdentityPublicKeyInCreationV0 { id: 0, key_type: ECDSA_SECP256K1, purpose: AUTHENTICATION, security_level: MASTER, contract_bounds: None, read_only: false, data: BinaryData(0x026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b), signature: BinaryData(0x) })], asset_lock_proof: Chain(ChainAssetLockProof { core_chain_locked_height: 1199074, out_point: OutPoint { txid: 0x762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1, vout: 0 } }), user_fee_increase: 0, signature: BinaryData(0x), identity_id: Identifier(IdentifierBytes32([90, 31, 92, 134, 2, 135, 134, 141, 135, 186, 27, 238, 194, 146, 89, 30, 71, 113, 112, 7, 56, 174, 248, 87, 190, 111, 179, 81, 113, 41, 147, 99])) })
//     // transition signable bytes: 00010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc00124be220b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000
//     // transition signature: 1fa237a83b4653752935da780bc2730fb37df5e250b4abacce302cf94ca50cd1ba7ebd4e339d532ce4fb9c8e01d91da9516d1cd96cf45f1193c0cfc24fa250a590
// }
//
// #[test]
// fn verify_chain_proof_signed_data() {
//     let chain_proof_signable_bytes = Vec::from_hex("0300010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc7fffffff20b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000")
//         .expect("Hex data");
//     // let chain_proof_signable_bytes = Vec::from_hex("0300010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b01fc00124be220762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb10000")
//     //     .expect("Hex data");
//     let signature = Vec::from_hex("207abce1bcd8bba4ba32a65478144837e4dad7fdb245d69de4645df5f0f298d11b608e3a2bdaea30d12d9d9449ee93e5ba5dc59fb36a80217fe0fb670fcaf5b1f4")
//         .expect("Hex data");
//     let identity = identity_fixture();
//     let public_key = identity.public_keys().first_key_value().unwrap().1;
//     let result = signer::verify_data_signature(&chain_proof_signable_bytes, signature.as_slice(), public_key.data().as_slice());
//     assert!(result.is_ok(), "Failed to verify signature");
// }
//
// #[test]
// fn verify_instant_proof_signed_data() {
//     let chain_proof_signable_bytes = Vec::from_hex("00010000000000000021026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b00a20000b16fcb9a165b8e14542becf5292b16f90650d13ad4b55fe20768db51d81020760000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ef03000800018ff03cc8d42a5e27be416d38e1b02718a111f03e6d7bfd178bd6cda26f33d3be010000006a4730440220765c83e5e908448ab2117a4abb806d21a3786d9642fc1883405c34367c1e5f3702207a0d1eae897e842b45632e57d02647ae193e8c7a247674399bc24d2d80799a88012102e25c6bbcbb1aa0a0c42283ded2d44e5c75551318a3c01d65906ac97aae1603e8ffffffff0240420f0000000000026a00c90ced02000000001976a914e97fe30aafd3666e70493b99cc35c0371d26654088ac0000000024010140420f00000000001976a91467575fc9d201b5ff36b5d8405497f1d961a56dbf88ac0000")
//         .expect("Hex data");
//     let signature = Vec::from_hex("1f4ee8736f228e9d6ecb4c1ee204c3fbd3310caf7bb08416bc784adaa81f1b9e7848bee1a8f72bc0cbb8da0e38ecef14033999b4ab861d865890e65fb50599e89c")
//         .expect("Hex data");
//     let identity = identity_fixture();
//     let public_key = identity.public_keys().first_key_value().unwrap().1;
//     let result = signer::verify_data_signature(&chain_proof_signable_bytes, signature.as_slice(), public_key.data().as_slice());
//     assert!(result.is_ok(), "Failed to verify signature");
// }
//
// // #[test]
// // fn test_identity_reg_transition_with_derivation() {
// //     let public_key_data = BinaryData::from_string("026ce9a9392503a57a8b4a4a16886f3cf5f5eacadbf62ca610c9d0fccc9a13eb4b", Encoding::Hex)
// //         .expect("Failed to create public key data");
// //     let public_key =  IdentityPublicKey::V0(IdentityPublicKeyV0 {
// //         id: 0,
// //         purpose: Purpose::AUTHENTICATION,
// //         security_level: SecurityLevel::MASTER,
// //         contract_bounds: None,
// //         key_type: KeyType::ECDSA_SECP256K1,
// //         read_only: false,
// //         data: public_key_data.clone(),
// //         disabled_at: None
// //     });
// //     let identity = Identity::V0(IdentityV0 {
// //         id: Identifier(IdentifierBytes32([98, 133, 105, 167, 166, 167, 34, 219, 173, 197, 92, 195, 127, 176, 26, 249, 89, 164, 21, 80, 121, 53, 90, 104, 119, 80, 167, 119, 212, 192, 32, 227])),
// //         public_keys: BTreeMap::from_iter([(
// //             0, public_key.clone())]),
// //         balance: 0,
// //         revision: 0,
// //     });
// //
// //     let seed_phrase = "birth kingdom trash renew flavor utility donkey gasp regular alert pave layer";
// //     let mnemonic = bip39::Mnemonic::from_str(seed_phrase).expect("Seed");
// //     let seed = mnemonic.to_seed("");
// //
// //     let proof_path = DerivationPath::bip_44_account(Network::Testnet, 0);
// //     let identity_path = DerivationPath::identity_registration_path(Network::Testnet, 0);
// //     let proof_key = proof_path.derive_priv_ecdsa_for_master_seed(&seed, Network::Testnet).expect("TODO: panic message");
// //     let identity_key = identity_path.derive_priv_ecdsa_for_master_seed(&seed, Network::Testnet).expect("TODO: panic message");
// //     let core_chain_locked_height = 1199074;
// //     let tx_id = <[u8; 32]>::from_hex("762010d851db6807e25fb5d43ad15006f9162b29f5ec2b54148e5b169acb6fb1").expect("???");
// //     let out_point = OutPoint { txid: Txid::from_slice(&tx_id).unwrap(), vout: 0 };
// //     let chain_proof = AssetLockProof::Chain(ChainAssetLockProof { core_chain_locked_height, out_point });
// //     let test_signer = TestSigner { private_key: key.private_key.secret_bytes().to_vec() };
// //     let mut transition: StateTransition =
// //         IdentityCreateTransition::try_from_identity_with_signer(
// //             &identity,
// //             chain_proof,
// //             proof_key.private_key.as_ref(),
// //             &test_signer,
// //             &NativeBlsModule,
// //             0,
// //             PlatformVersion::latest(),
// //         )
// //             .expect("expected an identity create transition");
// //     let result = transition.sign(&public_key, identity_key.private_key.as_ref(), &NativeBlsModule);
// //     assert!(result.is_ok(), "Failed to verify signature");
// // }
//
