use dash_sdk::platform::{DataContract, Fetch};
use dash_sdk::Error;
use platform_value::Identifier;
use crate::PlatformSDK;

// impl PlatformSDK {
//     pub async fn fetch_contract_by_id(&self, id: Identifier) -> Result<Option<DataContract>, Error> {
//         DataContract::fetch_by_identifier(self.sdk_ref(), id).await
//     }
// }