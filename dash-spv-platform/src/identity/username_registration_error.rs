use crate::document::usernames::UsernameStatus;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum UsernameRegistrationError {
    NoFullPathsWithStatus {
        status: UsernameStatus,
        next_status: Option<UsernameStatus>,
    },
    NoPreorderDocuments {
        status: UsernameStatus,
        next_status: Option<UsernameStatus>,
        username_full_paths: Vec<String>
    },
    NotSupported(UsernameStatus),
}