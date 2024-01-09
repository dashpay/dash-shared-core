use hashes::hex::FromHex;
use crate::chain::common::chain_type::DevnetType;
use crate::chain::common::ChainType;
use crate::crypto::byte_util::{Reversable, UInt256};

pub const DUFFS: u64 = 100000000;
pub(crate) const MAX_MONEY: u64 = 21000000 * DUFFS;
/// standard tx fee per b of tx size
pub(crate) const TX_FEE_PER_B: u64 = 1;
/// standard ix fee per input
pub(crate) const TX_FEE_PER_INPUT: u64 = 10000;
/// estimated size for a typical transaction output
pub(crate) const TX_OUTPUT_SIZE: u64 = 34;
/// estimated size for a typical compact pubkey transaction input
pub(crate) const TX_INPUT_SIZE: u64 = 148;
/// no txout can be below this amount
pub(crate) const TX_MIN_OUTPUT_AMOUNT: u64 = TX_FEE_PER_B * 3 * (TX_OUTPUT_SIZE + TX_INPUT_SIZE);
/// no tx can be larger than this size in bytes
pub(crate) const TX_MAX_SIZE: u64 = 100000;
/// block height indicating transaction is unconfirmed
pub const TX_UNCONFIRMED: i32 = i32::MAX;

pub(crate) const DEFAULT_FEE_PER_B: u64 = TX_FEE_PER_B;
/// minimum relay fee on a 191byte tx
pub(crate) const MIN_FEE_PER_B: u64 = TX_FEE_PER_B;
/// slightly higher than a 1000bit fee on a 191byte tx
pub(crate) const MAX_FEE_PER_B: u64 = 1000;

pub const DASH_PRIVKEY: u8 = 204;
pub const DASH_PRIVKEY_TEST: u8 = 239;
pub const DASH_PUBKEY_ADDRESS: u8 = 76;
pub const DASH_SCRIPT_ADDRESS: u8 = 16;
pub const DASH_PUBKEY_ADDRESS_TEST: u8 = 140;
pub const DASH_SCRIPT_ADDRESS_TEST: u8 = 19;

pub const BITCOIN_PUBKEY_ADDRESS: u8 = 0;
pub const BITCOIN_SCRIPT_ADDRESS: u8 = 5;
pub const BITCOIN_PUBKEY_ADDRESS_TEST: u8 = 111;
pub const BITCOIN_SCRIPT_ADDRESS_TEST: u8 = 196;
pub const BITCOIN_PRIVKEY: u8 = 128;
pub const BITCOIN_PRIVKEY_TEST: u8 = 239;

// pub const BIP38_NOEC_PREFIX: u16 = 0x0142;
// pub const BIP38_EC_PREFIX: u16 = 0x0143;
// pub const BIP38_NOEC_FLAG (0x80 | 0x40)
// pub const BIP38_COMPRESSED_FLAG 0x20
// pub const BIP38_LOTSEQUENCE_FLAG 0x04
// pub const BIP38_INVALID_FLAG (0x10 | 0x08 | 0x02 | 0x01)

pub const BIP32_SEED_KEY: &str = "Bitcoin seed";
pub const ED25519_SEED_KEY: &str = "ed25519 seed";

#[derive(Clone, Debug, Default)]
pub struct ScriptMap {
    // DASH_PRIVKEY | DASH_PRIVKEY_TEST
    pub privkey: u8,
    // DASH_PUBKEY_ADDRESS | DASH_PUBKEY_ADDRESS_TEST
    pub pubkey: u8,
    // DASH_SCRIPT_ADDRESS | DASH_SCRIPT_ADDRESS_TEST
    pub script: u8,
}

impl From<i16> for ScriptMap {
    fn from(value: i16) -> Self {
        ChainType::from(value).script_map()
    }
}

impl ScriptMap {
    pub const MAINNET: ScriptMap = ScriptMap {
        privkey: DASH_PRIVKEY,
        pubkey: DASH_PUBKEY_ADDRESS,
        script: DASH_SCRIPT_ADDRESS
    };
    pub const TESTNET: ScriptMap = ScriptMap {
        privkey: DASH_PRIVKEY_TEST,
        pubkey: DASH_PUBKEY_ADDRESS_TEST,
        script: DASH_SCRIPT_ADDRESS_TEST
    };
}

#[derive(Clone, Debug, Default)]
pub struct BIP32ScriptMap {
    pub xprv: [u8; 4],
    pub xpub: [u8; 4],
}

impl BIP32ScriptMap {
    pub const MAINNET: BIP32ScriptMap = BIP32ScriptMap { xprv: [b'\x04',b'\x88',b'\xAD',b'\xE4'], xpub: [b'\x04',b'\x88',b'\xB2',b'\x1E'] };
    pub const TESTNET: BIP32ScriptMap = BIP32ScriptMap { xprv: [b'\x04',b'\x35',b'\x83',b'\x94'], xpub: [b'\x04',b'\x35',b'\x87',b'\xCF'] };
}


#[derive(Clone, Debug, Default)]
pub struct DIP14ScriptMap {
    pub dps: [u8; 4],
    pub dpp: [u8; 4],
}

impl DIP14ScriptMap {
    pub const MAINNET: DIP14ScriptMap = DIP14ScriptMap { dps: [b'\x0E', b'\xEC', b'\xF0', b'\x2E'], dpp: [b'\x0E', b'\xEC', b'\xEF', b'\xC5'] };
    pub const TESTNET: DIP14ScriptMap = DIP14ScriptMap { dps: [b'\x0E', b'\xED', b'\x27', b'\x74'], dpp: [b'\x0E', b'\xED', b'\x27', b'\x0B'] };
}

// #[derive(Clone, Debug, Default)]
// pub struct Script

#[derive(Clone, Debug, Default)]
pub struct SporkParams {
    pub public_key_hex_string: Option<String>,
    pub private_key_base58_string: Option<String>,
    pub address: String,
}

#[derive(Clone, Debug, Default)]
pub struct Params {
    pub chain_type: ChainType,
    /// Mining and Dark Gravity Wave Parameters

    /// The lowest amount of work effort required to mine a block on the chain (higher values are less difficult)
    // pub max_proof_of_work: UInt256,
    pub max_proof_of_work: &'static str,
    /// The lowest amount of work effort required to mine a block on the chain. Here it is represented as the compact target (higher values are less difficult)
    pub max_proof_of_work_target: u32,
    /// Is set to true on networks where mining is low enough that it can be attacked by increasing difficulty with ASICs and then no longer running ASICs.
    /// This is set to false for Mainnet, and generally should be true on all other networks.
    pub allow_min_difficulty_blocks: bool,
    /// The base reward is the intial mining reward at genesis for the chain.
    /// This goes down by 7% every year.
    /// A SPV client does not validate that the reward amount is correct as it would not make sense
    /// for miners to enter incorrect rewards as the blocks would be rejected by full nodes.
    pub base_reward: u64,
    /// Spork parameters
    // pub spork_params: SporkParams,
    /// Protocol parameters
    /// The minimum protocol version that peers on this chain can communicate with. This should only be changed in the case of devnets
    pub min_protocol_version: u32,
    /// The protocol version that we currently use for this chain. This should only be changed in the case of devnets
    pub protocol_version: u32,
    pub standard_port: u16,
    pub standard_dapi_grpc_port: u32,
    /// The magic number is used in message headers to indicate what network (or chain) a message is intended for
    pub magic_number: u32,
    /// Is the maximum amount of headers that is expected from peers
    pub headers_max_amount: u32,
    pub peer_misbehaving_threshold: u32,
    pub transaction_version: u16,
    pub is_evolution_enabled: bool,
    pub fee_per_byte: u64,
    /// L2 Chain Parameters
    pub platform_protocol_version: u32,
    pub dpns_contract_id: &'static str,
    pub dashpay_contract_id: &'static str,
    pub minimum_difficulty_blocks: u32,
    pub standard_dapi_jrpc_port: u32,
    // pub script_map: ScriptMap,
    // pub bip32_script_map: BIP32ScriptMap,
    // pub dip14_script_map: DIP14ScriptMap,
}

pub const MAINNET_PARAMS: Params = Params {
    chain_type: ChainType::MainNet,
    max_proof_of_work: "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    max_proof_of_work_target: 0x1e0fffff,
    allow_min_difficulty_blocks: false,
    base_reward: 5 * DUFFS,
    // spork_params: SporkParams {
    //     public_key_hex_string: Some("04549ac134f694c0243f503e8c8a9a986f5de6610049c40b07816809b0d1d06a21b07be27b9bb555931773f62ba6cf35a25fd52f694d4e1106ccd237a7bb899fdd".to_string()),
    //     private_key_base58_string: None,
    //     address: "Xgtyuk76vhuFW2iT7UAiHgNdWXCf3J34wh".to_string()
    // },
    min_protocol_version: 70218,
    protocol_version: 70219,
    standard_port: 9999,
    standard_dapi_grpc_port: 3010,
    magic_number: 0xbd6b0cbf,
    headers_max_amount: 2000,
    peer_misbehaving_threshold: 20,
    transaction_version: 1,
    is_evolution_enabled: false,
    fee_per_byte: DEFAULT_FEE_PER_B,
    platform_protocol_version: 1,
    dpns_contract_id: "",
    dashpay_contract_id: "",
    minimum_difficulty_blocks: 0,
    standard_dapi_jrpc_port: 3000,
    // script_map: ScriptMap::MAINNET,
    // bip32_script_map: BIP32ScriptMap::MAINNET,
    // dip14_script_map: DIP14ScriptMap::MAINNET
};

pub const TESTNET_PARAMS: Params = Params {
    chain_type: ChainType::TestNet,
    max_proof_of_work: "00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    max_proof_of_work_target: 0x1e0fffff,
    allow_min_difficulty_blocks: true,
    base_reward: 50 * DUFFS,
    // spork_params: SporkParams {
    //     public_key_hex_string: Some("046f78dcf911fbd61910136f7f0f8d90578f68d0b3ac973b5040fb7afb501b5939f39b108b0569dca71488f5bbf498d92e4d1194f6f941307ffd95f75e76869f0e".to_string()),
    //     private_key_base58_string: None,
    //     address: "yjPtiKh2uwk3bDutTEA2q9mCtXyiZRWn55".to_string()
    // },
    min_protocol_version: 70218,
    protocol_version: 70220,
    standard_port: 19999,
    standard_dapi_grpc_port: 3010,
    magic_number: 0xffcae2ce,
    headers_max_amount: 2000,
    peer_misbehaving_threshold: 40,
    transaction_version: 1,
    is_evolution_enabled: false,
    fee_per_byte: DEFAULT_FEE_PER_B,
    platform_protocol_version: 1,
    dpns_contract_id: "GWRSAVFMjXx8HpQFaNJMqBV7MBgMK4br5UESsB4S31Ec",
    dashpay_contract_id: "Bwr4WHCPz5rFVAD87RqTs3izo4zpzwsEdKPWUT1NS1C7",
    minimum_difficulty_blocks: 0,
    standard_dapi_jrpc_port: 3000,
    // script_map: ScriptMap::TESTNET,
    // bip32_script_map: BIP32ScriptMap::TESTNET,
    // dip14_script_map: DIP14ScriptMap::TESTNET
};

pub fn create_devnet_params_for_type(r#type: DevnetType) -> Params {
    Params {
        chain_type: ChainType::DevNet(r#type),
        max_proof_of_work: "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        max_proof_of_work_target: 0x207fffff,
        allow_min_difficulty_blocks: true,
        base_reward: 50 * DUFFS,
        // spork_params: SporkParams {
        //     public_key_hex_string: None,
        //     private_key_base58_string: match r#type {
        //         DevnetType::Chacha => Some("cPTms6Sd7QuhPWXWQSzMbvg2VbEPsWCsLBbR4PBgvfYRzAPazbt3".to_string()),
        //         DevnetType::Devnet333 => Some("cQnP9JNQp6oaZrvBtqBWRMeQERMkDyuXyvQh1qaph4FdP6cT2cVa".to_string()),
        //         DevnetType::JackDaniels => Some("cTeGz53m7kHgA9L75s4vqFGR89FjYz4D9o44eHfoKjJr2ArbEtwg".to_string()),
        //         DevnetType::Mojito => Some("".to_string())
        //     },
        //     address: match r#type {
        //         DevnetType::Chacha => "ybiRzdGWFeijAgR7a8TJafeNi6Yk6h68ps".to_string(),
        //         DevnetType::Devnet333 => "yM6zJAMWoouAZxPvqGDbuHb6BJaD6k4raQ".to_string(),
        //         DevnetType::JackDaniels => "yYBanbwp2Pp2kYWqDkjvckY3MosuZzkKp7".to_string(),
        //         DevnetType::Mojito => "".to_string(),
        //     }
        // },
        min_protocol_version: 70219,
        protocol_version: 70225,
        standard_port: 20001,
        standard_dapi_grpc_port: 3010,
        magic_number: 0xceffcae2,
        headers_max_amount: 2000,
        peer_misbehaving_threshold: 3,
        transaction_version: 3,
        is_evolution_enabled: false,
        fee_per_byte: DEFAULT_FEE_PER_B,
        platform_protocol_version: 1,
        dpns_contract_id: "",
        dashpay_contract_id: "",
        minimum_difficulty_blocks: match r#type {
            DevnetType::JackDaniels => 4032,
            _ => 1000000,
        },
        standard_dapi_jrpc_port: 3000,
        // script_map: ScriptMap::TESTNET,
        // bip32_script_map: BIP32ScriptMap::TESTNET,
        // dip14_script_map: DIP14ScriptMap::TESTNET
    }
}

impl Params {
    pub fn max_proof_of_work(&self) -> UInt256 {
        UInt256::from_hex(self.max_proof_of_work).unwrap().reverse()
    }

    /// Contract Parameters
    pub fn dpns_contract_id(&self) -> UInt256 {
        UInt256::from_base58_string(self.dpns_contract_id).unwrap()
    }

    pub fn dashpay_contract_id(&self) -> UInt256 {
        UInt256::from_base58_string(self.dashpay_contract_id).unwrap()
    }

    /// Fee Parameters
    pub fn fee_for_tx_size(&self, size: u64) -> u64 {
        size * TX_FEE_PER_B
    }

    pub fn min_output_amount(&self) -> u64 {
        let amount: u64 = (TX_MIN_OUTPUT_AMOUNT * self.fee_per_byte + MIN_FEE_PER_B - 1) / MIN_FEE_PER_B;
        if amount > TX_MIN_OUTPUT_AMOUNT {
            amount
        } else {
            TX_MIN_OUTPUT_AMOUNT
        }
    }

    pub fn allow_insight_blocks_for_verification(&self) -> bool {
        self.chain_type != ChainType::MainNet
    }


    // if params.chain_type.is_mainnet() { params.dip14_script_map.dps } else { params.bip32_script_map.xprv }
}
