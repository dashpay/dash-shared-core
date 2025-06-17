use dash_spv_crypto::keys::OpaqueKey;

pub struct PotentialOneWayFriendship {
    pub source_identity_id: [u8; 32],
    pub destination_identity_id: Option<[u8; 32]>,
    pub destination_contact_id: Option<[u8; 32]>,
    pub extended_public_key: Option<OpaqueKey>,
    pub encrypted_extended_public_key_data: Option<Vec<u8>>,
    pub source_key_index: u32,
    pub destination_key_index: u32,
    pub created_at: u64,
}

impl PotentialOneWayFriendship {
    // pub fn to_value(&self) -> Value {
    //     let mut map = ValueMap::new();
    //     map.push((Value::Text("$createdAt".to_string()), Value::U64(self.created_at * 1000)));
    //     map.push((Value::Text("toUserId".to_string()), Value::Identifier(Hash256::from(self.destination_identity_id))));
    //     if let Some(ref data) = self.encrypted_extended_public_key_data {
    //         map.push((Value::Text("encryptedPublicKey".to_string()), Value::Bytes(data.clone())));
    //     }
    //     map.push((Value::Text("senderKeyIndex".to_string()), Value::U32(self.source_key_index)));
    //     map.push((Value::Text("recipientKeyIndex".to_string()), Value::U32(self.destination_key_index)));
    //     //let DOpaqueKeyCreateAccountRef([self sourceKeyAtIndex], self.extendedPublicKey->ok, self.account.accountNumber);
    //
    //     map.push((Value::Text("accountReference".to_string()), Value::U32(self.destination_key_index)));
    //
    //     // uintptr_t field_count = 6;
    //     // DValuePair **values = malloc(sizeof(DValuePair *) * field_count);
    //     // values[0] = DValueTextU64PairCtor(@"$createdAt", self.createdAt * 1000);
    //     // values[1] = DValueTextIdentifierPairCtor(@"toUserId", platform_value_Hash256_ctor(u256_ctor_u([self destinationIdentityUniqueId])));
    //     // values[2] = DValueTextBytesPairCtor(@"encryptedPublicKey", self.encryptedExtendedPublicKeyData);
    //     // values[3] = DValueTextU32PairCtor(@"senderKeyIndex", self.sourceKeyIndex);
    //     // values[4] = DValueTextU32PairCtor(@"recipientKeyIndex", self.destinationKeyIndex);
    //     // values[5] = DValueTextU32PairCtor(@"accountReference", [self createAccountReference]);
    //     // return platform_value_Value_Map_ctor(DValueMapCtor(DValuePairVecCtor(field_count, values)));
    //     Value::Map(map)
    // }

    // pub fn destination_key_at_index(&self) -> Option<OpaqueKey> {
    //     if let Some(destination_identity_id) = self.destination_identity_id {
    //         Some(OpaqueKey::from(destination_identity_id))
    //     } else if let Some(destination_contact_id) = self.destination_contact_id {
    //         Some(OpaqueKey::from(destination_contact_id))
    //     } else {
    //         None
    //     }
    // }


    // - (DOpaqueKey *)destinationKeyAtIndex {
    // if (self.destinationIdentity) {
    // return [self.destinationIdentity keyAtIndex:self.destinationKeyIndex];
    // } else if (self.destinationContact) {
    // return [self.destinationContact publicKeyAtIndex:self.destinationKeyIndex].pointerValue;
    // }
    // return nil;
    // }
}