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

#[proc_macro_derive(ChainManager)]
pub fn chain_manager_derive(input: TokenStream) -> TokenStream {
    let DeriveInput { ident, .. } = parse_macro_input!(input as DeriveInput);
    let expanded = quote! {
        impl dash_spv_keychain::KeychainRef for #ident {
            fn keychain_ref(&self) -> &dash_spv_keychain::KeychainController {
                self.chain.keychain_ref()
            }
        }
        impl dash_spv_storage::StorageRef for #ident {
            fn storage_ref(&self) -> &dash_spv_storage::controller::StorageController {
                self.chain.storage_ref()
            }
        }
        impl dash_spv_chain::wallet::WalletRef for #ident {
            fn wallet_ref(&self) -> &dash_spv_chain::wallet::WalletController {
                self.chain.wallet_ref()
            }
        }
        impl dash_spv_chain::derivation::DerivationRef for #ident {
            fn derivation_ref(&self) -> &dash_spv_chain::derivation::DerivationController {
                self.chain.derivation_ref()
            }
        }
    };
    TokenStream::from(expanded)
}
