pub trait CoinJoinMessage {
    fn get_message_type(&self) -> String;
}