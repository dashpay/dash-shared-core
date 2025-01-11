use dpp::document::{Document, DocumentV0Getters};
use dpp::prelude::{Revision, TimestampMillis};
use platform_value::{Hash256, Identifier, Value};

pub struct TransientDashPayUser {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub avatar_fingerprint: Option<Vec<u8>>,
    pub avatar_hash: Option<Hash256>,
    pub public_message: Option<String>,
    pub revision: Option<Revision>,
    pub document_identifier: Identifier,
    pub created_at: Option<TimestampMillis>,
    pub updated_at: Option<TimestampMillis>,
}
impl TransientDashPayUser {
    pub fn with_profile_document(document: Document) -> Self {
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