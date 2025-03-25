use dpp::document::{Document, DocumentV0Getters};
use platform_value::Value;

pub mod contact_request;
pub mod manager;
pub mod salted_domain_hashes;
pub mod usernames;

#[ferment_macro::export]
pub fn get_document_property(document: Document, property: &str) -> Option<Value> {
    document.properties()
        .get(property)
        .cloned()
}
#[ferment_macro::export]
pub fn print_document(document: Document) {
    println!("{}", document.to_string());
}