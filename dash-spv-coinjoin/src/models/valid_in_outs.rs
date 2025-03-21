use crate::messages::pool_message::PoolMessage;

#[derive(Clone)]
#[ferment_macro::export]
pub struct ValidInOuts {
    pub result: bool,
    pub message_id: PoolMessage,
    pub consume_collateral: bool
}

#[ferment_macro::export]
impl ValidInOuts {
    pub fn new() -> ValidInOuts {
        Self {
            result: true,
            message_id: PoolMessage::MsgNoErr,
            consume_collateral: false
        }
    }
}