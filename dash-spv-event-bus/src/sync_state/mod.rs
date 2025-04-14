use std::collections::HashSet;
use std::fmt::{Display, Formatter, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait KindOps {
    type Kind;
    fn add_kind(&mut self, kind: Self::Kind);
    fn remove_kind(&mut self, kind: &Self::Kind);
    fn reset_kind(&mut self);
}

pub trait Progress {
    fn progress(&self) -> f64;
}

pub trait Weight {
    fn weight(&self) -> f64;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[ferment_macro::export]
#[repr(u16)]
pub enum SyncStateScope {
    Chain = 0,
    Headers = 1,
    Masternodes = 2,
    Platform = 3,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[ferment_macro::export]
#[repr(u32)]
pub enum SyncStateKind {
    None = 0,
    Chain = 1,
    Headers = 2,
    Masternodes = 4,
    Platform = 8,
    Peers = 16,
    Governance = 32,
    MemPool = 64,
    Transactions = 128,
    CoinJoin = 256,
}
impl Display for SyncStateKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Chain => "Chain",
            Self::Headers => "Headers",
            Self::Masternodes => "Masternodes",
            Self::Platform => "Platform",
            Self::Peers => "Peers",
            Self::Governance => "Governance",
            Self::MemPool => "MemPool",
            Self::Transactions => "Transactions",
            Self::CoinJoin => "CoinJoin"
        })
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
#[ferment_macro::export]
pub enum PlatformSyncStateKind {
    None = 0,
    KeyHashes = 1,
    Unsynced = 2
}
impl Display for PlatformSyncStateKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::KeyHashes => "KeyHashes",
            Self::Unsynced => "Unsynced",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[ferment_macro::export]
#[repr(u16)]
pub enum PeersSyncStateKind {
    None = 0,
    Selection = 1,
    Connecting = 2
}
impl Display for PeersSyncStateKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Selection => "Selection",
            Self::Connecting => "Connecting",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[ferment_macro::export]
#[repr(u16)]
pub enum MasternodeListSyncStateKind {
    None = 0,
    Checkpoints = 1,
    Diffs = 2,
    QrInfo = 4,
    Quorums = 8,
}
impl Display for MasternodeListSyncStateKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::None => "None",
            Self::Checkpoints => "Checkpoints",
            Self::Diffs => "Diffs",
            Self::QrInfo => "QrInfo",
            Self::Quorums => "Quorums",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub struct HeadersSyncState {
    pub start_sync_height: u32,
    pub last_sync_height: u32,
    pub estimated_height: u32,
}

impl Display for HeadersSyncState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}/{}/{} = {:.2}]", self.start_sync_height, self.last_sync_height, self.estimated_height, self.progress()).as_str())
    }
}
impl Progress for HeadersSyncState {
    fn progress(&self) -> f64 {
        if /*!hasDownloadPeer && */self.start_sync_height == 0 {
            0f64
        } else if self.last_sync_height >= self.estimated_height {
            1f64
        } else {
            let ratio = if self.start_sync_height > self.last_sync_height {
                self.last_sync_height as f64 / self.estimated_height as f64
            } else {
                f64::from(self.last_sync_height - self.start_sync_height) / f64::from(self.estimated_height - self.start_sync_height)
            };
            f64::min(1.0, f64::max(0.0, 0.1 + 0.9 * ratio))
        }
    }
}
impl Weight for HeadersSyncState {
    fn weight(&self) -> f64 {
        if self.last_sync_height >= self.estimated_height {
            0f64
        } else {
            0.25 * f64::from(self.estimated_height - self.last_sync_height)
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub struct ChainSyncState {
    pub start_sync_height: u32,
    pub last_sync_height: u32,
    pub estimated_height: u32,
}

impl Display for ChainSyncState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}/{}/{} = {:.2}]", self.start_sync_height, self.last_sync_height, self.estimated_height, self.progress()).as_str())
    }
}
impl Progress for ChainSyncState {
    fn progress(&self) -> f64 {
        if /*!hasDownloadPeer && */self.start_sync_height == 0 {
            0f64
        } else if self.last_sync_height >= self.estimated_height {
            1f64
        } else if self.estimated_height == 0 {
            0f64
        } else if self.start_sync_height > self.last_sync_height {
            f64::min(1.0, f64::max(0.0, 0.1 + 0.9 * self.last_sync_height as f64 / self.estimated_height as f64))
        } else {

            let delta_sync_height = f64::from(self.estimated_height - self.start_sync_height);
            if delta_sync_height == 0.0 {
                0f64
            } else {
                f64::min(1.0, f64::max(0.0, 0.1 + 0.9 * (self.last_sync_height - self.start_sync_height) as f64 / delta_sync_height))
            }
        }
    }
}
impl Weight for ChainSyncState {
    fn weight(&self) -> f64 {
        if self.last_sync_height >= self.estimated_height {
            0f64
        } else {
            f64::from(self.estimated_height - self.last_sync_height)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub struct MasternodeListSyncState {
    pub queue_count: u32,
    pub queue_max_amount: u32,
    pub stored_count: u32,
    pub last_list_height: u32,
    pub estimated_height: u32,
    pub kind: HashSet<MasternodeListSyncStateKind>,
}
impl MasternodeListSyncState {
    pub fn lists_to_sync(&self) -> u32 {
        if self.queue_max_amount == 0 || self.stored_count <= 1 {
            if self.last_list_height == u32::MAX || self.estimated_height < self.last_list_height {
                24
            } else {
                u32::min(24, f64::ceil(f64::from(self.estimated_height - self.last_list_height) / 24f64) as u32)
            }
        } else {
            self.queue_count
        }
    }
}

impl Display for MasternodeListSyncState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}: {} {}/{} {}/{} = {:.3}]", self.kind.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | "), self.last_list_height, self.queue_count, self.queue_max_amount, self.stored_count, self.lists_to_sync(), self.progress()).as_str())
    }
}
impl Progress for MasternodeListSyncState {
    fn progress(&self) -> f64 {
        if self.queue_count > 0 && self.queue_max_amount > 0 {
            f64::max(f64::min(f64::from(self.queue_max_amount - self.queue_count) / self.queue_max_amount as f64, 1f64), 0f64)
        } else {
            f64::from(self.last_list_height != u32::MAX && self.estimated_height != 0 && self.last_list_height + 16 >= self.estimated_height)
        }
    }
}

impl Weight for MasternodeListSyncState {
    fn weight(&self) -> f64 {
        let lists_to_sync = self.lists_to_sync() as f64;
        if lists_to_sync > 0f64 {
            20000.0 + 2000.0 * (lists_to_sync - 1.0)
        } else {
            0f64
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub struct PlatformSyncState {
    pub queue_count: u32,
    pub queue_max_amount: u32,
    pub last_synced_timestamp: f64,
    pub kind: HashSet<PlatformSyncStateKind>,
}
impl PlatformSyncState {
    /// Returns if we synced identities in the last 30 seconds
    fn has_recent_identities_sync(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(Duration::as_secs_f64)
            .unwrap_or(0.0);
        now < self.last_synced_timestamp + 30.0
    }
}

impl Display for PlatformSyncState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}: {} {}/{} = {:.2}]", self.kind.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | "), self.last_synced_timestamp, self.queue_count, self.queue_max_amount, self.progress()).as_str())
    }
}
impl Progress for PlatformSyncState {
    fn progress(&self) -> f64 {
        if self.queue_count > 0 && self.queue_max_amount > 0 {
            f64::max(f64::min(f64::from(self.queue_max_amount - self.queue_count) / self.queue_max_amount as f64, 1f64), 0f64)
        } else {
            f64::from(self.has_recent_identities_sync())
        }
    }
}

impl Weight for PlatformSyncState {
    fn weight(&self) -> f64 {
        if self.queue_max_amount > 0 {
            20000.0 + 2000.0 * (self.queue_max_amount as f64 - 1.0)
        } else {
            0f64
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::export]
pub struct PeersSyncState {
    pub kind: HashSet<PeersSyncStateKind>,
    pub has_download_peer: bool,
    pub peer_manager_connected: bool,
}

impl Display for PeersSyncState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(format!("[{}: {}/{}]", self.kind.iter().map(ToString::to_string).collect::<Vec<_>>().join(" | "), self.has_download_peer, self.peer_manager_connected).as_str())
    }
}

impl Progress for PeersSyncState {
    fn progress(&self) -> f64 {
        f64::from(self.peer_manager_connected && self.has_download_peer)
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[ferment_macro::opaque]
pub struct SyncState {
    pub kind: HashSet<SyncStateKind>,

    pub chain_sync_state: ChainSyncState,
    pub headers_sync_state: HeadersSyncState,
    pub peers_sync_state: PeersSyncState,
    pub masternodes_sync_state: MasternodeListSyncState,
    pub platform_sync_state: PlatformSyncState,
}

#[ferment_macro::export]
impl SyncState {

    pub fn new() -> SyncState {
        Self {
            kind: HashSet::default(),
            chain_sync_state: ChainSyncState {
                start_sync_height: 0,
                last_sync_height: 0,
                estimated_height: 0,
            },
            headers_sync_state: HeadersSyncState {
                start_sync_height: 0,
                last_sync_height: 0,
                estimated_height: 0,
            },
            peers_sync_state: PeersSyncState {
                kind: HashSet::default(),
                has_download_peer: false,
                peer_manager_connected: false,
            },
            masternodes_sync_state: MasternodeListSyncState {
                queue_count: 0,
                queue_max_amount: 0,
                stored_count: 0,
                last_list_height: 0,
                estimated_height: 0,
                kind: HashSet::default(),
            },
            platform_sync_state: PlatformSyncState {
                queue_count: 0,
                queue_max_amount: 0,
                last_synced_timestamp: 0.0,
                kind: HashSet::default(),
            }}
    }
    pub fn update_estimated_height(&mut self, estimated_height: u32) {
        self.chain_sync_state.estimated_height = estimated_height;
        self.headers_sync_state.estimated_height = estimated_height;
        self.masternodes_sync_state.estimated_height = estimated_height;
    }

    pub fn peers_description(&self) -> String {
        self.peers_sync_state.to_string()
    }
    pub fn chain_description(&self) -> String {
        self.chain_sync_state.to_string()
    }
    pub fn headers_description(&self) -> String {
        self.headers_sync_state.to_string()
    }
    pub fn masternodes_description(&self) -> String {
        self.masternodes_sync_state.to_string()
    }
    pub fn platform_description(&self) -> String {
        self.platform_sync_state.to_string()
    }
}

impl Progress for SyncState {
     /// A unit of weight is the time it would take to sync 1000 blocks;
     /// terminal headers are 4 times faster the blocks
     /// the first masternode list is worth 20000 blocks
     /// each masternode list after that is worth 2000 blocks
    fn progress(&self) -> f64 {
         let chain_weight = self.chain_sync_state.weight();
         let terminal_weight = self.headers_sync_state.weight();
         let masternode_weight = self.masternodes_sync_state.weight();
         let platform_weight = self.platform_sync_state.weight();
         let total_weight = chain_weight + terminal_weight + masternode_weight + platform_weight;
         let has_download_peer = self.peers_sync_state.has_download_peer;
         if total_weight == 0.0 {
             self.peers_sync_state.progress()
         } else {
             let chain_progress = if !has_download_peer && self.chain_sync_state.start_sync_height == 0 {
                 0f64
             } else {
                 self.chain_sync_state.progress() * (chain_weight / total_weight)
             };
             let terminal_progress = if !has_download_peer && self.headers_sync_state.start_sync_height == 0 {
                 0f64
             } else {
                 self.headers_sync_state.progress() * (terminal_weight / total_weight)
             };
             let masternode_progress = self.masternodes_sync_state.progress() * (masternode_weight / total_weight);
             let platform_progress = self.platform_sync_state.progress() * (platform_weight / total_weight);
             let progress = chain_progress + terminal_progress + masternode_progress + platform_progress;
             if progress < 0.99995 {
                 progress
             } else {
                 1f64
             }
         }
    }
}

impl KindOps for SyncState {
    type Kind = SyncStateKind;

    fn add_kind(&mut self, kind: Self::Kind) {
        self.kind.insert(kind);
    }

    fn remove_kind(&mut self, kind: &Self::Kind) {
        self.kind.remove(kind);
    }

    fn reset_kind(&mut self) {
        self.kind.clear();
    }
}

impl KindOps for MasternodeListSyncState {
    type Kind = MasternodeListSyncStateKind;

    fn add_kind(&mut self, kind: Self::Kind) {
        self.kind.insert(kind);
    }

    fn remove_kind(&mut self, kind: &Self::Kind) {
        self.kind.remove(kind);
    }

    fn reset_kind(&mut self) {
        self.kind.clear();
    }
}
impl KindOps for PlatformSyncState {
    type Kind = PlatformSyncStateKind;

    fn add_kind(&mut self, kind: Self::Kind) {
        self.kind.insert(kind);
    }

    fn remove_kind(&mut self, kind: &Self::Kind) {
        self.kind.remove(kind);
    }

    fn reset_kind(&mut self) {
        self.kind.clear();
    }
}


impl KindOps for PeersSyncState {
    type Kind = PeersSyncStateKind;

    fn add_kind(&mut self, kind: Self::Kind) {
        self.kind.insert(kind);
    }

    fn remove_kind(&mut self, kind: &Self::Kind) {
        self.kind.remove(kind);
    }

    fn reset_kind(&mut self) {
        self.kind.clear();
    }
}
