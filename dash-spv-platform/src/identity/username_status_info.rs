use crate::document::usernames::UsernameStatus;

#[ferment_macro::export]
#[derive(Clone, Debug)]
pub struct UsernameStatusInfo {
    pub proper: Option<String>,
    pub domain: Option<String>,
    pub status: UsernameStatus,
    pub salt: [u8; 32],
}

impl UsernameStatusInfo {
    pub fn with_status(status: UsernameStatus) -> Self {
        Self {
            proper: None,
            domain: None,
            status,
            salt: [0u8; 32],
        }
    }
    pub fn confirmed(&self) -> Self {
        let mut s = self.clone();
        s.status = UsernameStatus::Confirmed;
        s
    }
}