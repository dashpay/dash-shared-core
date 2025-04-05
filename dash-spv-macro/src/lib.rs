extern crate proc_macro;
use syn::{DeriveInput, parse_macro_input};
use quote::quote;
use proc_macro::TokenStream;
#[proc_macro_derive(StreamManager)]
pub fn stream_manager_derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input as DeriveInput);
    let expanded = quote! {
        impl crate::util::StreamManager for #ident {
            fn sdk_ref(&self) -> &dash_sdk::Sdk {
                &self.sdk
            }
            fn chain_type(&self) -> &dash_spv_crypto::network::ChainType {
                &self.chain_type
            }
        }

    };
    TokenStream::from(expanded)
}
