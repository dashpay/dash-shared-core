
#[derive(Clone, Debug)]
#[ferment_macro::export]
pub enum StorageError {
    DatabaseError(String),
}