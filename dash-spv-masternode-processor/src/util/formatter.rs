use std::collections::{BTreeMap, HashSet};
use hashes::hex::ToHex;
use dash_spv_crypto::keys::OperatorPublicKey;
use dash_spv_crypto::llmq::LLMQEntry;
use dash_spv_crypto::network::LLMQType;
use crate::models::{MasternodeEntry, MasternodeList};

pub trait CustomFormatter {
    fn format(&self) -> String;
}
impl CustomFormatter for BTreeMap<LLMQType, BTreeMap<[u8; 32], LLMQEntry>> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, (llmq_type, map)| {
            acc.push_str(&format!("\t{}:\n", llmq_type));
            map.iter().for_each(|(h, entry)| {
                acc.push_str(&format!("\t\t{}:\n", h.to_hex()));
                acc.push_str(&format!("\t\t\t{}\n", entry));
            });
            acc
        })
    }
}
impl CustomFormatter for Vec<LLMQEntry> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, entry| {
            acc.push_str(&format!("\t{}:\n", entry));
            acc
        })
    }
}
impl CustomFormatter for BTreeMap<LLMQType, Vec<[u8; 32]>> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, (llmq_type, hashes)| {
            acc.push_str(&format!("\t{}:\n", llmq_type));
            acc.push_str(&format!("\t{}:\n", hashes.format()));
            acc
        })
    }
}
impl CustomFormatter for BTreeMap<[u8; 32], MasternodeEntry> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, (h, node)| {
            acc.push_str(&format!("{}: {}\n", h.to_hex(), node));
            acc
        })
    }
}
impl CustomFormatter for MasternodeList {
    fn format(&self) -> String {
        let MasternodeList { block_hash, known_height, masternode_merkle_root, llmq_merkle_root, masternodes, quorums } = self;
        let mut desc = format!("MasternodeList at {} ({}) merkle_roots: [mn: {}, llmq: {}]\n",
                               block_hash.to_hex(), known_height, masternode_merkle_root.unwrap_or([0u8; 32]).to_hex(), llmq_merkle_root.unwrap_or([0u8; 32]).to_hex());
        desc.push_str(masternodes.format().as_str());
        desc.push_str(quorums.format().as_str());
        desc
    }
}
impl CustomFormatter for Vec<MasternodeEntry> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, node| {
            acc.push_str(&format!("{}\n", node));
            acc
        })
    }
}
impl CustomFormatter for Vec<[u8; 32]> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, node| {
            acc.push_str(&format!("{}\n", node.to_hex()));
            acc
        })
    }
}
impl CustomFormatter for HashSet<[u8; 32]> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, node| {
            acc.push_str(&format!("\t{}\n", node.to_hex()));
            acc
        })
    }
}
impl CustomFormatter for Vec<OperatorPublicKey> {
    fn format(&self) -> String {
        self.iter().fold(String::new(), |mut acc, key| {
            acc.push_str(format!("\t{}:{},\n", key.version, key.data.to_hex()).as_str());
            acc
        })
    }
}
