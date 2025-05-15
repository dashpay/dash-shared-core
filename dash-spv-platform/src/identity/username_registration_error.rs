use crate::document::usernames::UsernameStatus;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum UsernameRegistrationError {
    NoUsernameFullPathsWithStatus(UsernameStatus),
    NoUsernamePreorderDocuments(UsernameStatus, Vec<String>),
    NotSupported(UsernameStatus),
}