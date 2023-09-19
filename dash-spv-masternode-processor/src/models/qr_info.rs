use byte::{BytesExt, TryRead};
use crate::models;
use crate::consensus::encode;
use crate::crypto::byte_util::BytesDecodable;
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
        let read_list_diff =
            |offset: &mut usize|
                models::MNListDiff::new(protocol_version, bytes, offset, |block_hash| provider.lookup_block_height_by_hash(block_hash));

        let read_snapshot = |offset: &mut usize| models::LLMQSnapshot::from_bytes(bytes, offset);
        let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(bytes, offset);



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
        provider.save_snapshot(diff_h_c.block_hash, snapshot_h_c.clone());
        provider.save_snapshot(diff_h_2c.block_hash, snapshot_h_2c.clone());
        provider.save_snapshot(diff_h_3c.block_hash, snapshot_h_3c.clone());
        if extra_share {
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
            provider.save_snapshot(block_hash, quorum_snapshot_list.get(i).unwrap().clone());
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

        // let version = bytes.read_with::<crate::common::LLMQVersion>(offset, LE)?;
        // let llmq_type = bytes.read_with::<crate::chain::common::LLMQType>(offset, LE)?;
        // let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?;
        // let index = if version.use_rotated_quorums() {
        //     Some(bytes.read_with::<u16>(offset, LE)?)
        // } else {
        //     None
        // };
        // let signers_count = bytes.read_with::<VarInt>(offset, LE)?;
        // let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
        // let signers_bitset: &[u8] = bytes.read_with(offset, Bytes::Len(signers_buffer_length))?;
        // let valid_members_count = bytes.read_with::<VarInt>(offset, LE)?;
        // let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
        // let valid_members_bitset: &[u8] =
        //     bytes.read_with(offset, Bytes::Len(valid_members_count_buffer_length))?;
        // let public_key = bytes.read_with::<UInt384>(offset, LE)?;
        // let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?;
        // let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?;
        // let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?;
        // Ok((QRInfoResult {
        //     result_at_tip,
        //     result_at_h,
        //     result_at_h_c,
        //     result_at_h_2c,
        //     result_at_h_3c,
        //     result_at_h_4c,
        //     snapshot_at_h_c,
        //     snapshot_at_h_2c,
        //     snapshot_at_h_3c,
        //     snapshot_at_h_4c,
        //     extra_share,
        //     last_quorum_per_index,
        //     quorum_snapshot_list,
        //     mn_list_diff_list
        // }, *offset))
    }
}
