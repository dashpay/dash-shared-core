
/*type Subscriber = Box<dyn Fn(Message) + Send + Sync>;

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub enum Event {
    MasternodeListChanged
}
#[derive(Clone, Debug)]
pub enum Message {

}
pub struct EventBus {
    handlers: Mutex<HashMap<Event, Vec<Subscriber>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self { handlers: Mutex::new(HashMap::new()) }
    }
    pub fn subscribe(&self, event: Event, handler: Subscriber) {
        let mut handlers = self.handlers.lock().unwrap();
        handlers.entry(event)
            .or_default()
            .push(handler);
    }
    pub fn publish(&self, event: Event, message: Message) {
        if let Some(subscribers) = self.handlers.lock().unwrap().get(&event) {
            for subscriber in subscribers {
                subscriber(message.clone());
            }
        }
    }
}
*/
use std::error::Error;

pub trait Linkable<Link> {
    fn link(&mut self, parent: &Link);
}

pub trait DAPIAddressHandler: Send + Sync {
    fn add_node(&self, address: [u8; 16]);
    fn remove_node(&self, address: [u8; 16]);
    fn add_nodes(&self, addresses: Vec<[u8; 16]>);
    fn remove_nodes(&self, node: Vec<[u8; 16]>);
}

pub trait MasternodeProvider {
    fn quorum_public_key<E>(&self, quorum_type: u32, quorum_hash: [u8; 32], core_chain_locked_height: u32) -> Result<[u8; 48], E> where E: Error;
}