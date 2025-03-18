use crate::messages::pool_message::PoolMessage;

pub struct ValidInOuts {
    pub result: bool,
    pub message_id: PoolMessage,
    pub consume_collateral: bool
}

impl ValidInOuts {
    pub fn new() -> Self {
        Self {
            result: true,
            message_id: PoolMessage::MsgNoErr,
            consume_collateral: false
        }
    }
}