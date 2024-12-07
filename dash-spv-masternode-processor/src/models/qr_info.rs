use byte::{BytesExt, TryRead};
use dash_spv_crypto::consensus::encode::VarInt;
use dash_spv_crypto::crypto::byte_util::BytesDecodable;
use dash_spv_crypto::llmq::entry::LLMQEntry;
use crate::models::{LLMQSnapshot, MNListDiff};
use crate::processing::MasternodeProcessor;

pub struct QRInfo {
    pub diff_tip: MNListDiff,
    pub diff_h: MNListDiff,
    pub diff_h_c: MNListDiff,
    pub diff_h_2c: MNListDiff,
    pub diff_h_3c: MNListDiff,
    pub diff_h_4c: Option<MNListDiff>,
    pub snapshot_h_c: LLMQSnapshot,
    pub snapshot_h_2c: LLMQSnapshot,
    pub snapshot_h_3c: LLMQSnapshot,
    pub snapshot_h_4c: Option<LLMQSnapshot>,
    pub extra_share: bool,
    pub last_quorum_per_index: Vec<LLMQEntry>,
    pub quorum_snapshot_list: Vec<LLMQSnapshot>,
    pub mn_list_diff_list: Vec<MNListDiff>,
}


pub type ReadContext<'a> = (&'a MasternodeProcessor, bool, u32, bool, *const std::os::raw::c_void);

impl<'a> TryRead<'a, ReadContext<'a>> for QRInfo {
    fn try_read(bytes: &'a [u8], ctx: ReadContext<'a>) -> byte::Result<(Self, usize)> {
        let mut offset = 0;
        let (processor, is_from_snapshot, protocol_version, is_rotated_quorums_presented, peer ) = ctx;
        let block_height_lookup = |block_hash|
            processor.provider.lookup_block_height_by_hash(block_hash);
        let read_list_diff = |offset: &mut usize|
            MNListDiff::new(bytes, offset, &*processor.provider, protocol_version);
        let read_snapshot = |offset: &mut usize|
            LLMQSnapshot::from_bytes(bytes, offset);
        let read_var_int = |offset: &mut usize|
            VarInt::from_bytes(bytes, offset);

        let snapshot_h_c = read_snapshot(&mut offset)?;
        let snapshot_h_2c = read_snapshot(&mut offset)?;
        let snapshot_h_3c = read_snapshot(&mut offset)?;
        let diff_tip = read_list_diff(&mut offset)?;
        if !is_from_snapshot {
            processor.should_process_diff_with_range(true, diff_tip.base_block_hash, diff_tip.block_hash, peer)
                .map_err(|er| byte::Error::BadInput { err: "Should not process this diff" })?;
                // .map_err(ProcessingError::from)?;
        }
        let diff_h = read_list_diff(&mut offset)?;
        let diff_h_c = read_list_diff(&mut offset)?;
        let diff_h_2c = read_list_diff(&mut offset)?;
        let diff_h_3c = read_list_diff(&mut offset)?;
        let extra_share = bytes.read_with::<bool>(&mut offset, ()).unwrap_or(false);
        let (snapshot_h_4c, diff_h_4c) = if extra_share {
            let snapshot_h_4c = read_snapshot(&mut offset)?;
            let diff_h_4c = read_list_diff(&mut offset)?;
            (Some(snapshot_h_4c), Some(diff_h_4c))
        } else {
            (None, None)
        };
        let mut llmq_snapshots_lock = processor.cache.llmq_snapshots.write().unwrap();

        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_c, block_height_lookup(diff_h_c.block_hash));
        llmq_snapshots_lock.insert(diff_h_c.block_hash, snapshot_h_c.clone());
        // processor.cache.save_snapshot(diff_h_c.block_hash, snapshot_h_c.clone());
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_2c, block_height_lookup(diff_h_2c.block_hash));
        llmq_snapshots_lock.insert(diff_h_2c.block_hash, snapshot_h_2c.clone());
        // processor.provider.save_snapshot(diff_h_2c.block_hash, snapshot_h_2c.clone());
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_3c, block_height_lookup(diff_h_3c.block_hash));
        llmq_snapshots_lock.insert(diff_h_3c.block_hash, snapshot_h_3c.clone());
        // processor.provider.save_snapshot(diff_h_3c.block_hash, snapshot_h_3c.clone());
        if extra_share {
            #[cfg(feature = "generate-dashj-tests")]
            crate::util::java::save_snapshot_to_json(snapshot_h_4c.as_ref().unwrap(), block_height_lookup(diff_h_4c.as_ref().unwrap().block_hash));
            llmq_snapshots_lock.insert(diff_h_4c.as_ref().unwrap().block_hash, snapshot_h_4c.clone().unwrap());
            // processor.provider.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_h_4c.clone().unwrap());
        }

        let last_quorum_per_index_count = read_var_int(&mut offset)?.0 as usize;

        let mut last_quorum_per_index: Vec<LLMQEntry> =
            Vec::with_capacity(last_quorum_per_index_count);
        let mut active_quorums_lock = processor.cache.active_quorums.write().unwrap();
        for _i in 0..last_quorum_per_index_count {
            let q = bytes.read_with::<LLMQEntry>(&mut offset, byte::LE)?;
            active_quorums_lock.insert(q.clone());
            last_quorum_per_index.push(q);
        }
        drop(active_quorums_lock);
        let quorum_snapshot_list_count = read_var_int(&mut offset)?.0 as usize;
        let mut quorum_snapshot_list: Vec<LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
        for _i in 0..quorum_snapshot_list_count {
            quorum_snapshot_list.push(bytes.read_with::<LLMQSnapshot>(&mut offset, byte::LE)?);
        }
        let mn_list_diff_list_count = read_var_int(&mut offset)?.0 as usize;
        let mut mn_list_diff_list: Vec<MNListDiff> = Vec::with_capacity(mn_list_diff_list_count);
        assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
        for i in 0..mn_list_diff_list_count {
            let list_diff = read_list_diff(&mut offset)?;
            let block_hash = list_diff.block_hash;
            mn_list_diff_list.push(list_diff);
            let snapshot = quorum_snapshot_list.get(i).unwrap();
            #[cfg(feature = "generate-dashj-tests")]
            crate::util::java::save_snapshot_to_json(&snapshot, block_height_lookup(block_hash));
            llmq_snapshots_lock.insert(block_hash, snapshot.clone());

            // provider.save_snapshot(block_hash, snapshot.clone());
        }
        drop(llmq_snapshots_lock);

        Ok((Self {
            diff_tip,
            diff_h,
            diff_h_c,
            diff_h_2c,
            diff_h_3c,
            diff_h_4c,
            snapshot_h_c,
            snapshot_h_2c,
            snapshot_h_3c,
            snapshot_h_4c,
            extra_share,
            last_quorum_per_index,
            quorum_snapshot_list,
            mn_list_diff_list,
        }, offset))
    }
}

// impl QRInfo {
//     pub fn into_result<F>(self, mut process_list_diff: F, is_rotated_quorums_presented: bool) -> QRInfoResult
//         where F: FnMut(MNListDiff, LLMQVerificationContext) -> MNListDiffResult {
//         QRInfoResult {
//             result_at_h_4c: self.diff_h_4c.map(|list_diff| process_list_diff(list_diff, LLMQVerificationContext::None)),
//             result_at_h_3c: process_list_diff(self.diff_h_3c, LLMQVerificationContext::None),
//             result_at_h_2c: process_list_diff(self.diff_h_2c, LLMQVerificationContext::None),
//             result_at_h_c: process_list_diff(self.diff_h_c, LLMQVerificationContext::None),
//             result_at_h: process_list_diff(self.diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented)),
//             result_at_tip: process_list_diff(self.diff_tip, LLMQVerificationContext::None),
//             // snapshot_at_h_c: self.snapshot_h_c,
//             // snapshot_at_h_2c: self.snapshot_h_2c,
//             // snapshot_at_h_3c: self.snapshot_h_3c,
//             // snapshot_at_h_4c: self.snapshot_h_4c,
//             // extra_share: self.extra_share,
//             // last_quorum_per_index: self.last_quorum_per_index,
//             quorum_snapshot_list: self.quorum_snapshot_list,
//             mn_list_diff_list: self.mn_list_diff_list
//                 .into_iter()
//                 .map(|list_diff| process_list_diff(list_diff, LLMQVerificationContext::None))
//                 .collect()
//         }
//     }
// }
