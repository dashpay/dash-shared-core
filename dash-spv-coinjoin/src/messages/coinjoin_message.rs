use crate::messages::{coinjoin_broadcast_tx, coinjoin_complete_message, coinjoin_final_transaction, coinjoin_status_update, CoinJoinCompleteMessage, CoinJoinFinalTransaction, CoinJoinStatusUpdate};
use crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx;

pub trait CoinJoinMessageType {
    fn get_message_type(&self) -> String;
}

#[ferment_macro::export]
pub enum CoinJoinMessage {
    StatusUpdate(CoinJoinStatusUpdate),
    BroadcastTx(CoinJoinBroadcastTx),
    FinalTransaction(CoinJoinFinalTransaction),
    Complete(CoinJoinCompleteMessage)
}

#[ferment_macro::export]
impl CoinJoinMessage {

    pub fn from_message(message: &[u8], message_type: &str) -> CoinJoinMessage {
        match message_type {
            "dssu" => CoinJoinMessage::StatusUpdate(coinjoin_status_update::from_message(message)),
            "dsf" => CoinJoinMessage::FinalTransaction(coinjoin_final_transaction::from_message(message)),
            "dsc" => CoinJoinMessage::Complete(coinjoin_complete_message::from_message(message)),
            "dstx" => CoinJoinMessage::BroadcastTx(coinjoin_broadcast_tx::from_message(message)),
            _ => panic!("CoinJoin: Unsupported message type")
        }
    }
}