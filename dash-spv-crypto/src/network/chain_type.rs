use crate::network::LLMQType;
use crate::crypto::byte_util::{Reversable, Reversed, UInt256};
use crate::util::{BIP32ScriptMap, DIP14ScriptMap, ScriptMap, SporkParams};
use crate::util::params::DUFFS;
use hashes::hex::FromHex;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

#[ferment_macro::export]
pub trait IHaveChainSettings {
    fn genesis_hash(&self) -> [u8; 32];
    fn genesis_height(&self) -> u32;
    fn is_llmq_type(&self) -> LLMQType;
    fn isd_llmq_type(&self) -> LLMQType;
    fn chain_locks_type(&self) -> LLMQType;
    fn platform_type(&self) -> LLMQType;
    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool;
    // {
    //     self.chain_locks_type() == llmq_type
    //         || self.is_llmq_type() == llmq_type
    //         || self.platform_type() == llmq_type
    //         || self.isd_llmq_type() == llmq_type
    // }
    fn is_evolution_enabled(&self) -> bool;
    fn name(&self) -> String;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[ferment_macro::export]
pub enum ChainType {
    #[default]
    MainNet,
    TestNet,
    DevNet(DevnetType),
}

// #[ferment_macro::export]
impl From<i16> for ChainType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => ChainType::MainNet,
            1 => ChainType::TestNet,
            _ => ChainType::DevNet(DevnetType::default()),
        }
    }
}

impl From<ChainType> for i16 {
    fn from(value: ChainType) -> Self {
        match value {
            ChainType::MainNet => 0,
            ChainType::TestNet => 1,
            ChainType::DevNet(..) => 2,
        }
    }
}
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
#[ferment_macro::export]
pub enum DevnetType {
    JackDaniels = 0,
    Devnet333 = 1,
    Chacha = 2,
    #[default]
    Mojito = 3,
    WhiteRussian = 4,
    MiningTest = 5,
    Mobile2 = 6,
    Zero = 7,
    Screwdriver = 8,
    Absinthe = 9,
    Bintang = 10,
    DRA = 11,
}

impl From<DevnetType> for ChainType {
    fn from(orig: DevnetType) -> Self {
        ChainType::DevNet(orig)
    }
}

impl From<ChainType> for DevnetType {
    fn from(orig: ChainType) -> Self {
        match orig {
            ChainType::DevNet(devnet_type) => devnet_type,
            _ => panic!("Can't get DevnetType from ChainType {:?}", orig),
        }
    }
}

impl From<i16> for DevnetType {
    fn from(orig: i16) -> Self {
        match orig {
            0 => DevnetType::JackDaniels,
            1 => DevnetType::Devnet333,
            2 => DevnetType::Chacha,
            3 => DevnetType::Mojito,
            4 => DevnetType::WhiteRussian,
            5 => DevnetType::MiningTest,
            6 => DevnetType::Mobile2,
            7 => DevnetType::Zero,
            8 => DevnetType::Screwdriver,
            9 => DevnetType::Absinthe,
            10 => DevnetType::Bintang,
            11 => DevnetType::DRA,
            _ => DevnetType::JackDaniels,
        }
    }
}

impl From<DevnetType> for i16 {
    fn from(value: DevnetType) -> Self {
        match value {
            DevnetType::JackDaniels => 0,
            DevnetType::Devnet333 => 1,
            DevnetType::Chacha => 2,
            DevnetType::Mojito => 3,
            DevnetType::WhiteRussian => 4,
            DevnetType::MiningTest => 5,
            DevnetType::Mobile2 => 6,
            DevnetType::Zero => 7,
            DevnetType::Screwdriver => 8,
            DevnetType::Absinthe => 9,
            DevnetType::Bintang => 10,
            DevnetType::DRA => 11,
        }
    }
}

impl From<&str> for DevnetType {
    fn from(value: &str) -> Self {
        match value {
            "devnet-jack-daniels" => DevnetType::JackDaniels,
            "devnet-333" => DevnetType::Devnet333,
            "devnet-chacha" => DevnetType::Chacha,
            "devnet-mojito" => DevnetType::Mojito,
            "devnet-white-russian" => DevnetType::WhiteRussian,
            "miningTest" => DevnetType::MiningTest,
            "devnet-mobile-2" => DevnetType::Mobile2,
            "0" => DevnetType::Zero,
            "devnet-screwdriver" => DevnetType::Screwdriver,
            "devnet-absinthe" => DevnetType::Absinthe,
            "devnet-bintang" => DevnetType::Bintang,
            "devnet-DRA" => DevnetType::DRA,
            _ => panic!("Devnet with name: {} not supported", value),
        }
    }
}

#[ferment_macro::export]
impl DevnetType {
    pub fn identifier(&self) -> String {
        match self {
            DevnetType::JackDaniels => "devnet-jack-daniels",
            DevnetType::Devnet333 => "devnet-333",
            DevnetType::Chacha => "devnet-chacha",
            DevnetType::Mojito => "devnet-mojito",
            DevnetType::WhiteRussian => "devnet-white-russian",
            DevnetType::MiningTest => "miningTest",
            DevnetType::Mobile2 => "devnet-mobile-2",
            DevnetType::Zero => "0",
            DevnetType::Screwdriver => "devnet-screwdriver",
            DevnetType::Absinthe => "devnet-absinthe",
            DevnetType::Bintang => "devnet-bintang",
            DevnetType::DRA => "devnet-DRA",
        }.to_string()
    }

    pub fn version(&self) -> u16 {
        1
    }
    pub fn index(&self) -> u16 {
        i16::from(*self) as u16
    }
}

#[ferment_macro::export]
impl IHaveChainSettings for ChainType {
    fn genesis_hash(&self) -> [u8; 32] {
        match self {
            ChainType::MainNet => UInt256::from_hex(
                "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
            )
            .unwrap()
            .reversed().0,
            ChainType::TestNet => UInt256::from_hex(
                "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
            )
            .unwrap()
            .reversed().0,
            ChainType::DevNet(devnet_type) => devnet_type.genesis_hash(),
        }
    }

    fn genesis_height(&self) -> u32 {
        self.is_devnet_any().into()
    }

    fn is_llmq_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype50_60,
            ChainType::TestNet => LLMQType::Llmqtype50_60,
            ChainType::DevNet(devnet_type) => devnet_type.is_llmq_type(),
        }
    }

    fn isd_llmq_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype60_75,
            ChainType::TestNet => LLMQType::Llmqtype60_75,
            ChainType::DevNet(devnet_type) => devnet_type.isd_llmq_type(),
        }
    }

    fn chain_locks_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype400_60,
            ChainType::TestNet => LLMQType::Llmqtype50_60,
            ChainType::DevNet(devnet_type) => devnet_type.chain_locks_type(),
        }
    }

    fn platform_type(&self) -> LLMQType {
        match self {
            ChainType::MainNet => LLMQType::Llmqtype100_67,
            ChainType::TestNet => LLMQType::Llmqtype25_67,
            ChainType::DevNet(devnet_type) => devnet_type.platform_type(),
        }
    }

    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool {
        self.chain_locks_type() == llmq_type
            || self.is_llmq_type() == llmq_type
            || self.platform_type() == llmq_type
            || self.isd_llmq_type() == llmq_type
    }

    fn is_evolution_enabled(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        match self {
            Self::MainNet => "Mainnet".to_string(),
            Self::TestNet => "Testnet".to_string(),
            Self::DevNet(devnet) => devnet.name(),
        }
    }
}

#[ferment_macro::export]
impl IHaveChainSettings for DevnetType {
    fn genesis_hash(&self) -> [u8; 32] {
        UInt256::from_hex(match self {
            DevnetType::JackDaniels => {
                "79ee40288949fd61132c025761d4f065e161d60a88aab4c03e613ca8718d1d26"
            },
            DevnetType::Chacha => {
                "8862eca4bdb5255b51dc72903b8a842f6ffe7356bc40c7b7a7437b8e4556e220"
            },
            DevnetType::Mojito => {
                "739507391fa00da48a2ecae5df3b5e40b4432243603db6dafe33ca6b4966e357"
            },
            DevnetType::WhiteRussian => {
                "9163d6958065ca5e73c36f0f2474ce618846260c215f5cba633bd0003585cb35"
            },
            DevnetType::Screwdriver => {
                "4ac35ceb629e529b2a0eb2e2676983d4b11ebddaff5bd00cae7156a02b521e6f"
            },
            DevnetType::Absinthe => {
                "53ab7716f36a92068d7bbfa6475681018788a438e028d8bfdf86bfff4f6b78ab"
            },
            _ => "00000bafbc94add76cb75e2ec92894837288a481e5c005f6563d91623bf8bc2c",
        })
        .unwrap()
        .reversed().0
    }

    fn genesis_height(&self) -> u32 {
        1
    }

    fn is_llmq_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnetDIP0024
    }

    fn isd_llmq_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnetDIP0024
    }

    fn chain_locks_type(&self) -> LLMQType {
        LLMQType::LlmqtypeDevnet
    }

    fn platform_type(&self) -> LLMQType {
        LLMQType::LlmqtypeTestnetPlatform
    }

    fn should_process_llmq_of_type(&self, llmq_type: LLMQType) -> bool {
        self.chain_locks_type() == llmq_type
            || self.is_llmq_type() == llmq_type
            || self.platform_type() == llmq_type
            || self.isd_llmq_type() == llmq_type
    }

    fn is_evolution_enabled(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        format!("Devnet - {}.{}", self.identifier(), self.version())
    }
}
// Params
#[ferment_macro::export]
impl ChainType {
    pub fn is_mainnet(&self) -> bool {
        *self == ChainType::MainNet
    }

    pub fn is_testnet(&self) -> bool {
        *self == ChainType::TestNet
    }

    pub fn is_devnet_any(&self) -> bool {
        !self.is_mainnet() && !self.is_testnet()
    }


    pub fn user_agent(&self) -> String {
        format!(
            "/dash-spv-core:{}{}/",
            env!("CARGO_PKG_VERSION"),
            match self {
                ChainType::MainNet => format!(""),
                ChainType::TestNet => format!("(testnet)"),
                ChainType::DevNet(devnet_type) => format!("(devnet.{})", devnet_type.identifier()),
            }
        )
    }

    pub fn coin_type(&self) -> u32 {
        if self.is_mainnet() {
            5
        } else {
            1
        }
    }

    pub fn devnet_identifier(&self) -> Option<String> {
        if let ChainType::DevNet(devnet_type) = self {
            Some(devnet_type.identifier())
        } else {
            None
        }
    }

    pub fn devnet_version(&self) -> Option<i16> {
        if let ChainType::DevNet(devnet_type) = self {
            Some(devnet_type.version() as i16)
        } else {
            None
        }
    }

    pub fn dns_seeds(&self) -> Vec<String> {
        match self {
            ChainType::MainNet => vec!["dnsseed.dash.org".to_string()],
            ChainType::TestNet => vec!["testnet-seed.dashdot.io".to_string()],
            ChainType::DevNet(_) => vec![],
        }
    }

    pub fn script_priv_key(&self) -> u8 {
        self.script_map().privkey
    }

    pub fn script_map(&self) -> ScriptMap {
        match self {
            ChainType::MainNet => ScriptMap::MAINNET,
            _ => ScriptMap::TESTNET,
        }
    }
    pub fn bip32_script_map(&self) -> BIP32ScriptMap {
        match self {
            ChainType::MainNet => BIP32ScriptMap::MAINNET,
            _ => BIP32ScriptMap::TESTNET,
        }
    }
    pub fn dip14_script_map(&self) -> DIP14ScriptMap {
        match self {
            ChainType::MainNet => DIP14ScriptMap::MAINNET,
            _ => DIP14ScriptMap::TESTNET,
        }
    }
    pub fn from_magic(magic: u32) -> Option<ChainType> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xbd6b0cbf => Some(Self::MainNet),
            0xffcae2ce => Some(Self::TestNet),
            _ => None
        }
    }

    pub fn magic(&self) -> u32 {
        match self {
            ChainType::MainNet => 0xbd6b0cbf,
            ChainType::TestNet => 0xffcae2ce,
            ChainType::DevNet(_) => 0xceffcae2,
        }
    }

    pub fn allow_min_difficulty_blocks(&self) -> bool {
        !self.is_mainnet()
    }

    pub fn max_proof_of_work(&self) -> UInt256 {
        UInt256::from_hex(if self.is_devnet_any() {
            "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        } else {
            "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        })
        .unwrap()
        .reverse()
    }

    pub fn max_proof_of_work_target(&self) -> u32 {
        if self.is_devnet_any() {
            0x207fffff
        } else {
            0x1e0fffff
        }
    }

    pub fn min_protocol_version(&self) -> u32 {
        match self {
            ChainType::MainNet => 70218,
            ChainType::TestNet => 70218,
            ChainType::DevNet(_) => 70219,
        }
    }

    pub fn protocol_version(&self) -> u32 {
        match self {
            ChainType::MainNet => 70230,
            ChainType::TestNet => 70230,
            ChainType::DevNet(_) => 70230
        }
    }

    pub fn use_legacy_bls(&self) -> bool {
        self.protocol_version() >= 70225
    }

    pub fn standard_port(&self) -> u16 {
        match self {
            ChainType::MainNet => 9999,
            ChainType::TestNet => 19999,
            ChainType::DevNet(_) => 20001,
        }
    }

    pub fn standard_dapi_grpc_port(&self) -> u16 {
        3010
    }

    pub fn standard_dapi_jrpc_port(&self) -> u16 {
        3000
    }

    pub fn localhost(&self) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0x7f000001), 0))
    }

    pub fn transaction_version(&self) -> u16 {
        match self {
            ChainType::MainNet => 1,
            ChainType::TestNet => 1,
            _ => 3,
        }
    }

    pub fn base_reward(&self) -> u64 {
        match self {
            ChainType::MainNet => 5 * DUFFS,
            _ => 50 * DUFFS,
        }
    }
    pub fn magic_number(&self) -> u64 {
        match self {
            ChainType::MainNet => 0xbd6b0cbf,
            ChainType::TestNet => 0xffcae2ce,
            ChainType::DevNet(..) => 0xceffcae2,
        }
    }

    pub fn header_max_amount(&self) -> u64 {
        2000
    }

    pub fn spork_params(&self) -> SporkParams {
        match self {
            ChainType::MainNet => SporkParams {
                public_key_hex_string: Some("04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd".to_string()),
                private_key_base58_string: None,
                address: "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh".to_string()
            },
            ChainType::TestNet => SporkParams {
                public_key_hex_string: Some("046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e".to_string()),
                private_key_base58_string: None,
                address: "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55".to_string()
            },
            ChainType::DevNet(devnet) => SporkParams {
                public_key_hex_string: None,
                private_key_base58_string: Some(match devnet {
                    DevnetType::Chacha => "cPTms6Sd7QuhPWXWQSzMbvg2VbEPsWCsLBbR4PBgvfYRzAPazbt3",
                    DevnetType::Devnet333 => "cQnP9JNQp6oaZrvBtqBWRMeQERMkDyuXyvQh1qaph4FdP6cT2cVa",
                    DevnetType::JackDaniels => "cTeGz53m7kHgA9L75s4vqFGR89FjYz4D9o44eHfoKjJr2ArbEtwg",
                    DevnetType::Screwdriver => "cUu1oagVnd2bBGC7EqyijjtFapiLb9yvmaWF4dMaREg6pmXJksHH",
                    DevnetType::Absinthe => "cSAqscqXqRSh9CuGDmdWjKjtVbdiPgCquVTRUFV8Atakx941edN7",
                    DevnetType::Bintang => "cSxYF3ndj46sMG6RKZMy9sBXG2qsXo9NQ6Ess1Jo3MzRRoX5EAEj",
                    _ => ""
                }.to_string()),
                address: match devnet {
                    DevnetType::Chacha => "ybiRzdGWFeijAgR7a8TJafeNi6Yk6h68ps",
                    DevnetType::Devnet333 => "yM6zJAMWoouAZxPvqGDbuHb6BJaD6k4raQ",
                    DevnetType::JackDaniels => "yYBanbwp2Pp2kYWqDkjvckY3MosuZzkKp7",
                    DevnetType::Screwdriver => "yibwxyuuKsP6kBsq74vu9p6ju97qEb2B4b",
                    DevnetType::Absinthe => "yQaxrDEMJ7t2d4eDTugn3FY87T78j3fJX3",
                    DevnetType::Bintang => "yZLSzMpkSk9aAYujdiMauQi4MYjQQwFgGQ",
                    _ => "",
                }.to_string()
            }
        }
    }

    pub fn peer_misbehaving_threshold(&self) -> usize {
        match self {
            ChainType::MainNet => 20,
            ChainType::TestNet => 40,
            ChainType::DevNet(_) => 4,
        }
    }

    pub fn core19_activation_height(&self) -> u32 {
        match self {
            ChainType::MainNet => 1899072,
            ChainType::TestNet => 850100,
            ChainType::DevNet(_) => 0,
        }
    }

    pub fn core20_activation_height(&self) -> u32 {
        match self {
            ChainType::MainNet => 1987776,
            ChainType::TestNet => 905100,
            _ => u32::MAX
        }
    }
    pub fn core20_is_active_at(&self, height: u32) -> bool {
        height >= self.core20_activation_height()
    }

    pub fn identifier(&self) -> String {
        match self {
            ChainType::MainNet => "mainnet".to_string(),
            ChainType::TestNet => "testnet".to_string(),
            ChainType::DevNet(dev) => dev.identifier()
        }
    }

    pub fn index(&self) -> u16 {
        match self {
            ChainType::MainNet => 0,
            ChainType::TestNet => 1,
            ChainType::DevNet(..) => 2
        }
    }
    pub fn devnet_type(&self) -> DevnetType {
        match self {
            ChainType::DevNet(devnet_type) => devnet_type.clone(),
            _ => panic!("Can't get DevnetType from ChainType {:?}", self),
        }
    }
}
#[ferment_macro::export]
pub fn chain_type_from_index(index: u16) -> ChainType {
    ChainType::from(index as i16)
}
#[ferment_macro::export]
pub fn devnet_type_from_index(index: u16) -> DevnetType {
    DevnetType::from(index as i16)
}#[ferment_macro::export]
pub fn devnet_type_from_identifier(identifier: &str) -> DevnetType {
    DevnetType::from(identifier)
}