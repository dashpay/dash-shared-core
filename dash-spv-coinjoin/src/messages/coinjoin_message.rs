use super::{CoinJoinCompleteMessage, CoinJoinFinalTransaction, CoinJoinStatusUpdate};

pub trait CoinJoinMessageType {
    fn get_message_type(&self) -> String;
}

pub enum CoinJoinMessage {
    StatusUpdate(CoinJoinStatusUpdate),
    FinalTransaction(CoinJoinFinalTransaction),
    Complete(CoinJoinCompleteMessage)
}
