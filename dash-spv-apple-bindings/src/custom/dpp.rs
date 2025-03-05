#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dpp::data_contract::document_type::index::LazyRegex)]
pub struct LazyRegexFFI(pub *mut dpp::data_contract::document_type::index::LazyRegex);
crate::impl_cloneable_ferment!(dpp::data_contract::document_type::index::LazyRegex, LazyRegexFFI);

#[allow(non_camel_case_types)]
#[derive(Clone)]
#[ferment_macro::register(dpp::data_contract::associated_token::token_configuration::TokenConfiguration)]
pub struct TokenConfigurationFFI(pub *mut dpp::data_contract::associated_token::token_configuration::TokenConfiguration);
crate::impl_cloneable_ferment!(dpp::data_contract::associated_token::token_configuration::TokenConfiguration, TokenConfigurationFFI);
