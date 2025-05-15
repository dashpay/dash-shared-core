use crate::document::usernames::UsernameStatus;

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub enum SaveUsernameContext {
    NewUsername {
        username: String,
        domain: String,
        status: UsernameStatus,
        salt: Option<[u8; 32]>,
        commit_save: bool,
    },
    Username {
        username: String,
        domain: String,
        status: UsernameStatus,
        salt: Option<[u8; 32]>,
        commit_save: bool,
    },
    UsernameFullPath {
        username_full_path: String,
        status: UsernameStatus,
        salt: Option<[u8; 32]>,
        commit_save: bool,
    },
    UsernameFullPaths {
        username_full_paths: Vec<String>,
        status: UsernameStatus,
    }
}

impl SaveUsernameContext {
    pub fn new_username(username: &str, domain: &str, status: UsernameStatus, salt: Option<[u8; 32]>, commit_save: bool) -> SaveUsernameContext {
        SaveUsernameContext::NewUsername {
            username: username.to_string(),
            domain: domain.to_string(),
            status,
            salt,
            commit_save,
        }
    }
    pub fn username(username: &str, domain: &str, status: UsernameStatus, salt: Option<[u8; 32]>, commit_save: bool) -> SaveUsernameContext {
        SaveUsernameContext::NewUsername {
            username: username.to_string(),
            domain: domain.to_string(),
            status,
            salt,
            commit_save,
        }
    }

    pub fn confirmed_username(username: &str, domain: &str) -> SaveUsernameContext {
        SaveUsernameContext::Username {
            username: username.to_string(),
            domain: domain.to_string(),
            status: UsernameStatus::Confirmed,
            salt: None,
            commit_save: true,
        }
    }

    pub fn salted_username(username: String, domain: String, salt: [u8; 32], status: UsernameStatus) -> SaveUsernameContext {
        SaveUsernameContext::Username {
            username,
            domain,
            status,
            salt: Some(salt),
            commit_save: true,
        }
    }
    pub fn confirmed_username_full_paths(username_full_paths: Vec<String>) -> SaveUsernameContext {
        SaveUsernameContext::UsernameFullPaths {
            username_full_paths,
            status: UsernameStatus::Confirmed,
        }
    }
    pub fn preordered_username_full_paths(username_full_paths: Vec<String>) -> SaveUsernameContext {
        SaveUsernameContext::UsernameFullPaths {
            username_full_paths,
            status: UsernameStatus::Preordered,
        }
    }

    pub fn initial_username_full_paths(username_full_paths: Vec<String>) -> SaveUsernameContext {
        SaveUsernameContext::UsernameFullPaths {
            username_full_paths,
            status: UsernameStatus::Initial,
        }
    }
    pub fn preordered_username_full_path(username_full_path: &str) -> SaveUsernameContext {
        SaveUsernameContext::UsernameFullPath {
            username_full_path: username_full_path.to_string(),
            status: UsernameStatus::Preordered,
            salt: None,
            commit_save: true,
        }
    }
}
