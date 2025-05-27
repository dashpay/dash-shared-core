use dpp::document::{Document, DocumentV0Getters};
use dpp::prelude::{Revision, TimestampMillis};
use platform_value::{Identifier, Value};
use crate::error::Error;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct TransientDashPayUser {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub avatar_fingerprint: Option<Vec<u8>>,
    pub avatar_hash: Option<[u8; 32]>,
    pub public_message: Option<String>,
    pub revision: Option<Revision>,
    pub document_identifier: Identifier,
    pub created_at: Option<TimestampMillis>,
    pub updated_at: Option<TimestampMillis>,
}

#[ferment_macro::export]
impl TransientDashPayUser {
    pub fn is_updated_after(&self, timestamp: u64) -> bool {
        match self.updated_at {
            None => false,
            Some(updated_at) => updated_at > timestamp
        }
    }
}

impl TryFrom<&Document> for TransientDashPayUser {
    type Error = Error;

    fn try_from(document: &Document) -> Result<Self, Self::Error> {
        let avatar_url = if let Some(Value::Text(avatar_url)) = document.get("avatarUrl") {
            Some(avatar_url.clone())
        } else {
            None
        };
        let avatar_fingerprint = if let Some(Value::Bytes(avatar_fingerprint)) = document.get("avatarFingerprint") {
            Some(avatar_fingerprint.clone())
        } else {
            None
        };
        let avatar_hash = if let Some(Value::Identifier(avatar_fingerprint)) = document.get("avatarHash") {
            Some(avatar_fingerprint.clone())
        } else {
            None
        };
        let public_message = if let Some(Value::Text(public_message)) = document.get("publicMessage") {
            Some(public_message.clone())
        } else {
            None
        };
        let display_name = if let Some(Value::Text(public_message)) = document.get("displayName") {
            Some(public_message.clone())
        } else {
            None
        };
        Ok(Self {
            revision: document.revision(),
            avatar_url,
            avatar_fingerprint,
            avatar_hash,
            public_message,
            display_name,
            created_at: document.created_at(),
            updated_at: document.updated_at(),
            document_identifier: document.id()
        })
    }
}
impl TransientDashPayUser {
    pub fn with_profile_document(document: Document) -> Self {
        let avatar_url = document.get("avatarUrl")
            .and_then(|value| value.as_text())
            .map(|text| text.to_string());
        let avatar_fingerprint = document.get("avatarFingerprint")
            .and_then(|value| value.as_bytes())
            .cloned();

        let avatar_hash = if let Some(Value::Bytes32(avatar_hash)) = document.get("avatarHash") {
            Some(avatar_hash.clone())
        } else {
            None
        };
        let public_message = document.get("publicMessage")
            .and_then(|value| value.as_text())
            .map(|text| text.to_string());
        let display_name = document.get("displayName")
            .and_then(|value| value.as_text())
            .map(|text| text.to_string());
        Self {
            revision: document.revision(),
            avatar_url,
            avatar_fingerprint,
            avatar_hash,
            public_message,
            display_name,
            created_at: document.created_at(),
            updated_at: document.updated_at(),
            document_identifier: document.id()
        }
    }
}