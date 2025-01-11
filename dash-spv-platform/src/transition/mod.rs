use dashcore::{InstantLock, OutPoint, Transaction, TxIn, TxOut, Txid};
use dashcore::bls_sig_utils::BLSSignature;
use dashcore::hash_types::CycleHash;
use dashcore::hashes::Hash;
use dashcore::transaction::special_transaction::asset_lock::AssetLockPayload;
use dashcore::transaction::special_transaction::TransactionPayload;
use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
use dpp::identity::identity_public_key::v0::IdentityPublicKeyV0;
use dpp::identity::{IdentityPublicKey, KeyType};
use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
use dpp::identity::state_transition::asset_lock_proof::chain::ChainAssetLockProof;
use platform_value::BinaryData;
use dash_spv_crypto::keys::{IKey, OpaqueKey};
use dash_spv_crypto::tx::{TransactionInput, TransactionOutput};

#[ferment_macro::export]
pub fn identity_registration_public_key(index: u32, public_key: OpaqueKey) -> IdentityPublicKey {
    IdentityPublicKey::V0(IdentityPublicKeyV0 {
        id: index,
        purpose: Purpose::AUTHENTICATION,
        security_level: SecurityLevel::MASTER,
        contract_bounds: None,
        key_type: KeyType::ECDSA_SECP256K1,
        read_only: false,
        data: BinaryData(public_key.public_key_data()),
        disabled_at: None,
    })
}



#[ferment_macro::export]
pub fn instant_proof(
    output_index: u32,
    lock_version: u8, lock_inputs: Vec<[u8; 36]>, txid: [u8; 32], cycle_hash: [u8; 32], signature: [u8; 96],
    tx_version: u16, lock_time: u32, input: Vec<TransactionInput>, output: Vec<TransactionOutput>,
    asset_lock_payload_version: u8, credit_outputs: Vec<TransactionOutput>
) -> AssetLockProof {
    AssetLockProof::Instant(InstantAssetLockProof {
        instant_lock: InstantLock {
            version: lock_version,
            inputs: Vec::from_iter(lock_inputs.into_iter().map(OutPoint::from)),
            txid: Txid::from_byte_array(txid),
            cyclehash: CycleHash::from_byte_array(cycle_hash),
            signature: BLSSignature::from(signature),
        },
        transaction: Transaction {
            version: tx_version,
            lock_time,
            input: Vec::from_iter(input.into_iter().map(TxIn::from)),
            output: Vec::from_iter(output.into_iter().map(TxOut::from)),
            special_transaction_payload: Some(TransactionPayload::AssetLockPayloadType(AssetLockPayload {
                version: asset_lock_payload_version,
                credit_outputs: Vec::from_iter(credit_outputs.into_iter().map(TxOut::from)),
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

#[test]
fn test_identity_funding_transaction_unique_id() {
    use base64::{alphabet, Engine, engine::{GeneralPurpose, GeneralPurposeConfig}};
    use dashcore::bls_sig_utils::BLSSignature;
    use dashcore::consensus::Decodable;
    use dashcore::hash_types::CycleHash;
    use dashcore::hashes::{sha256d, Hash};
    use dashcore::secp256k1::ThirtyTwoByteHash;
    use dashcore::{signer, Txid};
    use dash_spv_crypto::hashes::hex::{FromHex, ToHex};
    use dash_spv_crypto::keys::{ECDSAKey, IKey};
    use dash_spv_crypto::tx::credit_funding::{CreditFunding, CreditFundingTransaction};
    use dpp::dashcore::InstantLock;
    use dpp::identity::identity_public_key::{Purpose, SecurityLevel};
    use dpp::identity::KeyType;
    use dpp::identity::state_transition::asset_lock_proof::{AssetLockProof, InstantAssetLockProof};
    use dpp::serialization::{PlatformSerializable, Signable};
    use dpp::state_transition::identity::identity_create_transition::IdentityCreateTransition;
    use dpp::state_transition::identity::identity_create_transition::v0::IdentityCreateTransitionV0;
    use dpp::state_transition::identity::public_key_in_creation::IdentityPublicKeyInCreation;
    use dpp::state_transition::identity::public_key_in_creation::v0::IdentityPublicKeyInCreationV0;
    use dpp::state_transition::StateTransition;
    use platform_value::{BinaryData, Identifier};
    use platform_value::string_encoding::Encoding;
    use dash_spv_crypto::crypto::byte_util::Reversed;
    use dash_spv_crypto::crypto::UInt256;

    let base64_engine = GeneralPurpose::new(&alphabet::STANDARD, GeneralPurposeConfig::default());
    let mut signature = [0u8; 96];
    signature[0] = 1;

    let bls_signature = BLSSignature::from(signature);

    let tx_data = Vec::from_hex("0300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000").unwrap();
    let mut transaction_data = tx_data.as_slice();
    let funding_tx = CreditFundingTransaction::from(transaction_data);
    let hash = funding_tx.base.tx_hash().unwrap();
    let txid = Txid::from_slice(&hash).unwrap();
    let is_lock = InstantLock {
        version: 0,
        inputs: vec![],
        txid,
        cyclehash: CycleHash::from_raw_hash(sha256d::Hash::from_slice(&[0u8; 32]).unwrap()),
        signature: bls_signature,
    };
    assert_eq!(is_lock.request_id().unwrap().to_hex(), UInt256::from_hex("7bab86a676ac6cd3ab0b8180f37121a36d8ae6fecea59e7c4e7783ce9cb84696").unwrap().reversed().0.to_hex());

    let funding_tx_locked_outpoint = funding_tx.locked_outpoint().unwrap();
    let transaction = dashcore::blockdata::transaction::Transaction::consensus_decode(&mut transaction_data).unwrap();
    assert_eq!(txid, transaction.txid(), "ddd");
    let transaction_locked_outpoint = transaction.locked_outpoint().unwrap();
    let out_index = transaction_locked_outpoint.vout;
    let instant_asset_lock_proof = InstantAssetLockProof::new(is_lock, transaction, out_index);
    let identifier = instant_asset_lock_proof.create_identifier().unwrap();
    println!("Identifier: {}", identifier);
    let asset_lock_proof = AssetLockProof::Instant(instant_asset_lock_proof);

    println!("funding_tx_locked_outpoint tx_id: {}", funding_tx_locked_outpoint.txid.to_hex());
    println!("funding_tx_locked_outpoint vout: {}", funding_tx_locked_outpoint.vout);
    println!("transaction_locked_outpoint tx_id: {}", transaction_locked_outpoint.txid.to_hex());
    println!("transaction_locked_outpoint vout: {}", transaction_locked_outpoint.vout);
    let credit_burn_identity_id = funding_tx.credit_burn_identity_identifier();



    assert_eq!(credit_burn_identity_id.to_hex(), "ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string(), "Credit Burn Identity Identifier is incorrect");
    // assert_eq!(credit_burn_identity_id.to_hex(), transaction.credit_burn_identity_identifier().to_hex(), "Credit Burn Identity Identifier is incorrect");
    let credit_burn_public_key_hash = funding_tx.credit_burn_public_key_hash().unwrap();
    assert_eq!(credit_burn_public_key_hash.to_hex(), "14ec6c36e6c39a9181f3a261a08a5171425ac5e2".to_string(), "Credit Burn Identity Public Key Hash is incorrect");
    // assert_eq!(credit_burn_public_key_hash.to_hex(), transaction.credit_burn_public_key_hash().unwrap().to_hex(), "Credit Burn Identity Public Key Hash is incorrect");
    let identity_identifier =  funding_tx.credit_burn_identity_identifier_base58();
    assert_eq!(identity_identifier, "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
    // assert_eq!(transaction.credit_burn_identity_identifier_base58(), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string(), "Identity Identifier is incorrect");
    let public_key = ECDSAKey::key_with_public_key_data(&base64_engine.decode("AsPvyyh6pkxss/Fespa7HCJIY8IA6ElAf6VKuqVcnPze").unwrap()).unwrap();
    let private_key_data = Vec::from_hex("fdbca0cd2be4375f04fcaee5a61c5d170a2a46b1c0c7531f58c430734a668f32").unwrap();
    let private_key = ECDSAKey::key_with_secret_data(&private_key_data, true).unwrap();
    let public_key_data = private_key.public_key_data();
    assert_eq!(public_key_data.to_hex(), "02c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde".to_string(), "Public Key Data is incorrect");
    assert_eq!(public_key.hash160(), credit_burn_public_key_hash, "The private key doesn't match the funding transaction");

    // AssetLockProof:
    // if (self.creditFundingTransaction.instantSendLockAwaitingProcessing) {
    //     assetLockDictionary[@"type"] = @(0);
    //     assetLockDictionary[@"instantLock"] = self.creditFundingTransaction.instantSendLockAwaitingProcessing.toData;
    //     assetLockDictionary[@"outputIndex"] = @(self.creditFundingTransaction.lockedOutpoint.n);
    //     assetLockDictionary[@"transaction"] = [self.creditFundingTransaction toData];
    // } else {
    //     assetLockDictionary[@"type"] = @(1);
    //     assetLockDictionary[@"coreChainLockedHeight"] = @(self.creditFundingTransaction.blockHeight);
    //     assetLockDictionary[@"outPoint"] = dsutxo_data(self.creditFundingTransaction.lockedOutpoint);
    // }
    let mut transition = StateTransition::IdentityCreate(IdentityCreateTransition::V0(IdentityCreateTransitionV0 {
        public_keys: vec![IdentityPublicKeyInCreation::V0(IdentityPublicKeyInCreationV0 {
            id: 1,
            key_type: KeyType::ECDSA_SECP256K1,
            purpose: Purpose::AUTHENTICATION,
            security_level: SecurityLevel::MASTER,
            contract_bounds: None,
            read_only: false,
            data: BinaryData(public_key_data),
            signature: Default::default(),
        })],
        asset_lock_proof,
        user_fee_increase: 0,
        signature: Default::default(),
        // self.blockchainIdentityUniqueId = [dsutxo_data(creditFundingTransaction.lockedOutpoint) SHA256_2];

        identity_id: Identifier::from(funding_tx.credit_burn_identity_identifier()),
    }));
    // let identity_public_key = IdentityPublicKey::V0()

    let data = transition.signable_bytes().unwrap();
    println!("sign_id: {}", data.to_hex());
    let signature = signer::sign(&data, &private_key_data).unwrap();
    transition.set_signature(signature.to_vec().into());

    assert_eq!(transition.owner_id().to_string(Encoding::Base58), "Cka1ELdpfrZhFFvKRurvPtTHurDXXnnezafNPJkxCYjc".to_string());
    // 7c4855e4230f5705498b2209bb3bebbe337684af58b9b21bb235bf8a31138951
    println!("Transition Owner ID: {}", transition.owner_id());
    println!("Transition Signature: {}", transition.signature().to_vec().to_hex());
    println!("Transition Serialized to bytes: {}", transition.serialize_to_bytes().unwrap().to_hex());
    let hashed = sha256d::Hash::hash(&transition.serialize_to_bytes().unwrap()).into_32();
    println!("Transition SHA256-2: {}", hashed.to_hex());

    let result = "0001000100000000004104c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde9ad99fb575a4dc3eeacb835c9b607e54a436aef621cfc09797984bcb325c8e3c0000a20100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff00ffffffff01ffffffffffffffff0000000000000000ae99d9433fc86f8974094c6a24fcc8cc68f87510c000d714c71ee5f64ceacf4b".to_string();
    let result = transition.serialize_to_bytes().unwrap().to_hex();
    let etalon = "01000000a4647479706502697369676e617475726558411fe06d3cd2671ec7f6653eb45f40ab4bce27f42a46893997042f87b344913aee3b794aeaf632b4887516a7765b2329569d45176fe7e090defc1a077889a93fdf076a7075626c69634b65797381a6626964016464617461582102c3efcb287aa64c6cb3f15eb296bb1c224863c200e849407fa54abaa55c9cfcde64747970650067707572706f73650068726561644f6e6c79f46d73656375726974794c6576656c006e61737365744c6f636b50726f6f66a46474797065006b696e7374616e744c6f636b58810025847e1e9c2ef692d21bc23a6c0faf8834d64704e5e0186427d3444bc75c1ba50100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006b6f7574707574496e646578006b7472616e73616374696f6e5901950300000002b74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417020000006b483045022100815b175ab1a8fde7d651d78541ba73d2e9b297e6190f5244e1957004aa89d3c902207e1b164499569c1f282fe5533154495186484f7db22dc3dc1ccbdc9b47d997250121027f69794d6c4c942392b1416566aef9eaade43fbf07b63323c721b4518127baadffffffffb74030bbda6edd804d4bfb2bdbbb7c207a122f3af2f6283de17074a42c6a5417010000006b483045022100a7c94fe1bb6ffb66d2bb90fd8786f5bd7a0177b0f3af20342523e64291f51b3e02201f0308f1034c0f6024e368ca18949be42a896dda434520fa95b5651dc5ad3072012102009e3f2eb633ee12c0143f009bf773155a6c1d0f14271d30809b1dc06766aff0ffffffff031027000000000000166a1414ec6c36e6c39a9181f3a261a08a5171425ac5e210270000000000001976a91414ec6c36e6c39a9181f3a261a08a5171425ac5e288acc443953b000000001976a9140d1775b9ed85abeb19fd4a7d8cc88b08a29fe6de88ac00000000".to_string();

    // println!("transition_serialized: {}", transition_serialized.to_hex());
    // [blockchainIdentityRegistrationTransition signWithKey:privateKey atIndex:UINT32_MAX fromIdentity:nil];
    // let transition_signed = private_key.sign(&transition_serialized);
    // println!("transition_signed: {}", transition_signed.to_hex());
}