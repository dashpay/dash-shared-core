use byte::{BytesExt, TryRead};
use crate::{models, processing};
use crate::consensus::encode;
use crate::crypto::byte_util::BytesDecodable;
use crate::models::LLMQVerificationContext;
use crate::processing::CoreProvider;

pub struct QRInfo {
    pub diff_tip: models::mn_list_diff::MNListDiff,
    pub diff_h: models::mn_list_diff::MNListDiff,
    pub diff_h_c: models::mn_list_diff::MNListDiff,
    pub diff_h_2c: models::mn_list_diff::MNListDiff,
    pub diff_h_3c: models::mn_list_diff::MNListDiff,
    pub diff_h_4c: Option<models::mn_list_diff::MNListDiff>,
    pub snapshot_h_c: models::snapshot::LLMQSnapshot,
    pub snapshot_h_2c: models::snapshot::LLMQSnapshot,
    pub snapshot_h_3c: models::snapshot::LLMQSnapshot,
    pub snapshot_h_4c: Option<models::snapshot::LLMQSnapshot>,
    pub extra_share: bool,
    pub last_quorum_per_index: Vec<models::llmq_entry::LLMQEntry>,
    pub quorum_snapshot_list: Vec<models::snapshot::LLMQSnapshot>,
    pub mn_list_diff_list: Vec<models::mn_list_diff::MNListDiff>,
}


pub type ReadContext<'a> = (&'a dyn CoreProvider, bool, u32, bool);

impl<'a> TryRead<'a, ReadContext<'a>> for QRInfo {
    fn try_read(bytes: &'a [u8], ctx: ReadContext<'a>) -> byte::Result<(Self, usize)> {
        let mut offset = 0;
        let provider = ctx.0;
        let is_from_snapshot = ctx.1;
        let protocol_version = ctx.2;
        let is_rotated_quorums_presented = ctx.3;
        let block_height_lookup = |block_hash|
            provider.lookup_block_height_by_hash(block_hash);
        let read_list_diff = |offset: &mut usize|
            models::MNListDiff::new( bytes, offset, block_height_lookup, protocol_version);
        let read_snapshot = |offset: &mut usize|
            models::LLMQSnapshot::from_bytes(bytes, offset);
        let read_var_int = |offset: &mut usize|
            encode::VarInt::from_bytes(bytes, offset);

        let snapshot_h_c = read_snapshot(&mut offset)?;
        let snapshot_h_2c = read_snapshot(&mut offset)?;
        let snapshot_h_3c = read_snapshot(&mut offset)?;
        let diff_tip = read_list_diff(&mut offset)?;
        if !is_from_snapshot {
            provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash)
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
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_c, block_height_lookup(diff_h_c.block_hash));
        provider.save_snapshot(diff_h_c.block_hash, snapshot_h_c.clone());
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_2c, block_height_lookup(diff_h_2c.block_hash));
        provider.save_snapshot(diff_h_2c.block_hash, snapshot_h_2c.clone());
        #[cfg(feature = "generate-dashj-tests")]
        crate::util::java::save_snapshot_to_json(&snapshot_h_3c, block_height_lookup(diff_h_3c.block_hash));
        provider.save_snapshot(diff_h_3c.block_hash, snapshot_h_3c.clone());
        if extra_share {
            #[cfg(feature = "generate-dashj-tests")]
            crate::util::java::save_snapshot_to_json(snapshot_h_4c.as_ref().unwrap(), block_height_lookup(diff_h_4c.as_ref().unwrap().block_hash));
            provider.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_h_4c.clone().unwrap());
        }

        let last_quorum_per_index_count = read_var_int(&mut offset)?.0 as usize;

        let mut last_quorum_per_index: Vec<models::LLMQEntry> =
            Vec::with_capacity(last_quorum_per_index_count);
        for _i in 0..last_quorum_per_index_count {
            last_quorum_per_index.push(bytes.read_with::<models::LLMQEntry>(&mut offset, byte::LE)?);
        }
        let quorum_snapshot_list_count = read_var_int(&mut offset)?.0 as usize;
        let mut quorum_snapshot_list: Vec<models::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
        for _i in 0..quorum_snapshot_list_count {
            quorum_snapshot_list.push(bytes.read_with::<models::LLMQSnapshot>(&mut offset, byte::LE)?);
        }
        let mn_list_diff_list_count = read_var_int(&mut offset)?.0 as usize;
        let mut mn_list_diff_list: Vec<models::MNListDiff> = Vec::with_capacity(mn_list_diff_list_count);
        assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
        for i in 0..mn_list_diff_list_count {
            let list_diff = read_list_diff(&mut offset)?;
            let block_hash = list_diff.block_hash;
            mn_list_diff_list.push(list_diff);
            let snapshot = quorum_snapshot_list.get(i).unwrap();
            #[cfg(feature = "generate-dashj-tests")]
            crate::util::java::save_snapshot_to_json(&snapshot, block_height_lookup(block_hash));
            provider.save_snapshot(block_hash, snapshot.clone());
        }

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

impl QRInfo {
    pub fn into_result<F: FnMut(models::MNListDiff, LLMQVerificationContext) -> processing::MNListDiffResult>(self, mut process_list_diff: F, is_rotated_quorums_presented: bool) -> processing::QRInfoResult {
        processing::QRInfoResult {
            result_at_h_4c: self.diff_h_4c.map(|list_diff| process_list_diff(list_diff, LLMQVerificationContext::None)),
            result_at_h_3c: process_list_diff(self.diff_h_3c, LLMQVerificationContext::None),
            result_at_h_2c: process_list_diff(self.diff_h_2c, LLMQVerificationContext::None),
            result_at_h_c: process_list_diff(self.diff_h_c, LLMQVerificationContext::None),
            result_at_h: process_list_diff(self.diff_h, LLMQVerificationContext::QRInfo(is_rotated_quorums_presented)),
            result_at_tip: process_list_diff(self.diff_tip, LLMQVerificationContext::None),
            snapshot_at_h_c: self.snapshot_h_c,
            snapshot_at_h_2c: self.snapshot_h_2c,
            snapshot_at_h_3c: self.snapshot_h_3c,
            snapshot_at_h_4c: self.snapshot_h_4c,
            extra_share: self.extra_share,
            last_quorum_per_index: self.last_quorum_per_index,
            quorum_snapshot_list: self.quorum_snapshot_list,
            mn_list_diff_list: self.mn_list_diff_list
                .into_iter()
                .map(|list_diff| process_list_diff(list_diff, LLMQVerificationContext::None))
                .collect()
        }
    }
}
