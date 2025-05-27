use dpp::document::{Document, DocumentV0Getters};
use platform_value::Value;
use crate::error::Error;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum ContactRequestKind {
    Incoming(ContactRequest),
    Outgoing(ContactRequest),
}

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct ContactRequest {
    pub id: [u8; 32],
    pub owner_id: [u8; 32],
    pub recipient: [u8; 32],
    pub encrypted_account_label: Option<Vec<u8>>,
    pub encrypted_public_key: Vec<u8>,
    pub account_reference: i64,
    pub sender_key_index: i64,
    pub recipient_key_index: i64,
    pub created_at: u64,
}

impl TryFrom<Document> for ContactRequest {
    type Error = Error;

    fn try_from(value: Document) -> Result<Self, Self::Error> {
        let id = value.id().to_buffer();
        let owner_id = value.owner_id().to_buffer();
        let created_at = value.created_at()
            .ok_or(Error::DashSDKError("created_at not present".to_string()))?;
        let props = value.properties_consumed();
        let recipient = props.get("toUserId")
            .and_then(|value| value.to_identifier().map(|identifier| identifier.into_buffer()).ok())
            .ok_or(Error::DashSDKError("toUserId not present".to_string()))?;
        let encrypted_public_key = props.get("encryptedPublicKey")
            .and_then(|value| value.as_bytes().cloned())
            .ok_or(Error::DashSDKError("encryptedPublicKey not present".to_string()))?;

        let encrypted_account_label = props.get("encryptedAccountLabel")
            .and_then(|value| value.as_bytes().cloned());
        let account_reference = if let Some(Value::I64(val)) = props.get("accountReference") {
            *val
        } else {
            0
        };
        let sender_key_index = if let Some(Value::I64(val)) = props.get("senderKeyIndex") {
            *val
        } else {
            return Err(Error::DashSDKError("senderKeyIndex not present".to_string()));
        };
        let recipient_key_index = if let Some(Value::I64(val)) = props.get("recipientKeyIndex") {
            *val
        } else {
            return Err(Error::DashSDKError("recipientKeyIndex not present".to_string()));
        };
        Ok(ContactRequest {
            id,
            owner_id,
            recipient,
            encrypted_account_label,
            encrypted_public_key,
            account_reference,
            sender_key_index,
            recipient_key_index,
            created_at,
        })
    }
}

