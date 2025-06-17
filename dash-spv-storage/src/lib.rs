use crate::controller::StorageController;

pub mod controller;
pub mod entity;
pub mod error;
pub mod predicate;
pub mod entities;

pub trait StorageRef {
    fn storage_ref(&self) -> &StorageController;
}

#[derive(Copy, Clone, Debug)]
#[ferment_macro::export]
pub enum StorageContext {
    None,
    View,
    Peer,
    Chain,
    Platform,
    Masternodes,
}

#[ferment_macro::export]
impl StorageContext {
    pub fn index(&self) -> u8 {
        match self {
            StorageContext::None => 0,
            StorageContext::View => 1,
            StorageContext::Peer => 2,
            StorageContext::Chain => 3,
            StorageContext::Platform => 4,
            StorageContext::Masternodes => 5
        }
    }
    pub fn from_index(index: u8) -> StorageContext {
        match index {
            1 => StorageContext::View,
            2 => StorageContext::Peer,
            3 => StorageContext::Chain,
            4 => StorageContext::Platform,
            5 => StorageContext::Masternodes,
            _ => StorageContext::None,
        }
    }

    pub fn is_none(&self) -> bool {
        matches!(self, StorageContext::None)
    }
}


