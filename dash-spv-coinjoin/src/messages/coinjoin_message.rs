use super::{coinjoin_broadcast_tx::CoinJoinBroadcastTx, CoinJoinCompleteMessage, CoinJoinFinalTransaction, CoinJoinStatusUpdate};

pub trait CoinJoinMessageType {
    fn get_message_type(&self) -> String;
}

pub enum CoinJoinMessage {
    StatusUpdate(CoinJoinStatusUpdate),
    BroadcastTx(CoinJoinBroadcastTx),
    FinalTransaction(CoinJoinFinalTransaction),
    Complete(CoinJoinCompleteMessage)
}
