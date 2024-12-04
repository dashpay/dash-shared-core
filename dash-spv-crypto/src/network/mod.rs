pub mod chain_type;
pub mod constants;
pub mod llmq_type;
pub mod protocol;
pub use self::chain_type::{ChainType, DevnetType, IHaveChainSettings};
pub use self::llmq_type::{LLMQParams, LLMQType};

pub const DASH_MESSAGE_MAGIC: &str = "DarkCoin Signed Message:\n";

pub const CORE_PROTO_BLS_BASIC: u32 = 70225;
pub const CORE_PROTO_19: u32 = 70227;
pub const CORE_PROTO_19_2: u32 = 70228;
pub const CORE_PROTO_DIFF_VERSION_ORDER: u32 = 70229;
pub const CORE_PROTO_20: u32 = 70230;

pub const CHAIN_LOCK_ACTIVATION_HEIGHT: u32 = 1088640;
