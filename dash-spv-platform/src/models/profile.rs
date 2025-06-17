use std::collections::BTreeMap;
use platform_value::{Value, ValueMap};

#[derive(Clone)]
#[ferment_macro::export]
pub struct ProfileModel {
    pub profile: Profile,
    pub entropy_data: [u8; 32],
    pub document_id: [u8; 32],
}

#[derive(Clone)]
#[ferment_macro::export]
pub struct Profile {
    pub updated_at: u64,
    pub created_at: u64,
    pub revision: u64,
    pub public_message: Option<String>,
    pub avatar_url: Option<String>,
    pub avatar_fingerprint: Option<Vec<u8>>,
    pub avatar_hash: Option<Vec<u8>>,
    pub display_name: Option<String>,
}

impl Profile {
    pub fn to_value(&self) -> Value {
        let mut props = ValueMap::new();
        props.push((Value::Text("$updatedAt".to_string()), Value::U64(self.updated_at)));
        if self.created_at == self.updated_at {
            props.push((Value::Text("$createdAt".to_string()), Value::U64(self.created_at)));
        } else {
            props.push((Value::Text("$revision".to_string()), Value::U64(self.revision)));
        }
        if let Some(ref public_message) = self.public_message {
            props.push((Value::Text("publicMessage".to_string()), Value::Text(public_message.clone())));
        }
        if let Some(ref avatar_url) = self.avatar_url {
            props.push((Value::Text("avatarUrl".to_string()), Value::Text(avatar_url.clone())));
        }
        if let Some(ref avatar_fingerprint) = self.avatar_fingerprint {
            props.push((Value::Text("avatarFingerprint".to_string()), Value::Bytes(avatar_fingerprint.clone())));
        }
        if let Some(ref avatar_hash) = self.avatar_hash {
            props.push((Value::Text("avatarHash".to_string()), Value::Bytes(avatar_hash.clone())));
        }
        if let Some(ref display_name) = self.display_name {
            props.push((Value::Text("displayName".to_string()), Value::Text(display_name.clone())));
        }
        Value::Map(props)
    }

    pub fn to_prevalidated_properties(&self) -> BTreeMap<String, Value> {
        let mut props = BTreeMap::new();
        props.insert("$updatedAt".to_string(), Value::U64(self.updated_at));
        if self.created_at == self.updated_at {
            props.insert("$createdAt".to_string(), Value::U64(self.created_at));
        } else {
            props.insert("$revision".to_string(), Value::U64(self.revision));
        }
        if let Some(ref public_message) = self.public_message {
            props.insert("publicMessage".to_string(), Value::Text(public_message.clone()));
        }
        if let Some(ref avatar_url) = self.avatar_url {
            props.insert("avatarUrl".to_string(), Value::Text(avatar_url.clone()));
        }
        if let Some(ref avatar_fingerprint) = self.avatar_fingerprint {
            props.insert("avatarFingerprint".to_string(), Value::Bytes(avatar_fingerprint.clone()));
        }
        if let Some(ref avatar_hash) = self.avatar_hash {
            props.insert("avatarHash".to_string(), Value::Bytes(avatar_hash.clone()));
        }
        if let Some(ref display_name) = self.display_name {
            props.insert("displayName".to_string(), Value::Text(display_name.clone()));
        }
        props
    }
}