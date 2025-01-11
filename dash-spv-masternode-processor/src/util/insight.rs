const INSIGHT_URL: &str = "https://insight.dash.org/insight-api";
const TESTNET_INSIGHT_URL: &str = "https://insight.testnet.networks.dash.org:3002/insight-api-dash";

use serde::Deserialize;
use std::error::Error;
use hashes::hex::{FromHex, ToHex};
use dash_spv_crypto::crypto::byte_util::Reversed;
use crate::common::Block;
use crate::common::block::MBlock;

#[derive(Debug, Deserialize)]
struct BlockResponse {
    version: u32,
    hash: String,
    previousblockhash: String,
    merkleroot: String,
    time: u64,
    bits: String,
    chainwork: String,
    height: u32,
}

#[derive(Debug)]
pub struct InsightBlock {
    version: u32,
    block_hash: [u8; 32],
    previous_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    timestamp: u64,
    target: u32,
    chain_work: [u8; 32],
    height: u32,
}
impl From<InsightBlock> for MBlock {
    fn from(value: InsightBlock) -> Self {
        MBlock {
            height: value.height,
            hash: value.block_hash,
            merkle_root: value.merkle_root.reversed()
        }
    }
}
impl From<InsightBlock> for Block {
    fn from(value: InsightBlock) -> Self {
        Block {
            height: value.height,
            hash: value.block_hash,
        }
    }
}

fn insight_block_by_url(insight_url: String, by: String) -> Result<InsightBlock, Box<dyn Error>> {
    let url = format!("{}/block/{}", insight_url, by);
    println!("GET: {url}");
    let json = reqwest::blocking::get(&url).unwrap().json::<BlockResponse>()?;
    let block_hash = <[u8; 32]>::from_hex(&json.hash)?;
    let previous_block_hash = <[u8; 32]>::from_hex(&json.previousblockhash)?;
    let merkle_root = <[u8; 32]>::from_hex(&json.merkleroot)?;
    let chain_work = <[u8; 32]>::from_hex(&json.chainwork)?;
    let target_bytes = Vec::from_hex(&json.bits)?;
    let target = u32::from_be_bytes(target_bytes[0..4].try_into().unwrap());
    let block = InsightBlock {
        version: json.version,
        block_hash,
        previous_block_hash,
        merkle_root,
        timestamp: json.time,
        target,
        chain_work,
        height: json.height,
    };
    println!("From insight: {} {}", block.height, block.block_hash.to_hex());
    Ok(block)
}

pub fn insight_block_by_block_hash(insight_url: String, block_hash: &[u8; 32]) -> Result<InsightBlock, Box<dyn Error>> {
    insight_block_by_url(insight_url, block_hash.to_hex())
}
pub fn insight_block_by_block_height(insight_url: String, block_height: u32) -> Result<InsightBlock, Box<dyn Error>> {
    insight_block_by_url(insight_url, block_height.to_string())
}
