// use std::error::Error;
// use dpp::dashcore::OutPoint;
// use dash_spv_crypto::tx::Transaction;
// use crate::identity::model::IdentityModel;
//
// pub struct Invitation {
//
//     /// This is the identity that was made from the invitation.
//     /// There should always be an identity associated to a blockchain invitation.
//     /// This identity might not yet be registered on Dash Platform.
//     pub identity: Option<IdentityModel>,
//
//     /// This is an invitation that was created locally.
//     pub created_locally: bool,
//
//     /// This is an invitation that was created with an external link, and has not yet retrieved the identity.
//     pub needs_identity_retrieval,
//
//     /// This is the wallet holding the blockchain invitation. There should always be a wallet associated to a blockchain invitation.
//     pub wallet: Option<Wallet>,
//
//     /// A name for locally created invitation.
//     pub name: String,
//
//     /// A tag for locally created invitation.
//     pub tag: String
//
// }
