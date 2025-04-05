// use dpp::identity::Identity;
// use crate::models::transient_dashpay_user::TransientDashPayUser;
//
//
// #[derive(Clone, Debug)]
// #[ferment_macro::opaque]
// pub struct IdentityContext {
//     pub wallet_id: String,
// }
//
// #[derive(Clone, Debug)]
// #[ferment_macro::export]
// pub struct IdentityModel {
//     pub context: IdentityContext,
//     pub identity: Identity,
//     pub transient_dash_pay_user: Option<TransientDashPayUser>
// }