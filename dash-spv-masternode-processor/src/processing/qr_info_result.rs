#[derive(Clone, Debug)]
#[rs_ffi_macro_derive::impl_ffi_conv]
pub struct QRInfoResult {
    pub result_at_tip: crate::processing::mn_listdiff_result::MNListDiffResult,
    pub result_at_h: crate::processing::mn_listdiff_result::MNListDiffResult,
    pub result_at_h_c: crate::processing::mn_listdiff_result::MNListDiffResult,
    pub result_at_h_2c: crate::processing::mn_listdiff_result::MNListDiffResult,
    pub result_at_h_3c: crate::processing::mn_listdiff_result::MNListDiffResult,
    pub result_at_h_4c: Option<crate::processing::mn_listdiff_result::MNListDiffResult>,

    pub snapshot_at_h_c: crate::models::snapshot::LLMQSnapshot,
    pub snapshot_at_h_2c: crate::models::snapshot::LLMQSnapshot,
    pub snapshot_at_h_3c: crate::models::snapshot::LLMQSnapshot,
    pub snapshot_at_h_4c: Option<crate::models::snapshot::LLMQSnapshot>,

    pub extra_share: bool,
    pub last_quorum_per_index: Vec<crate::models::llmq_entry::LLMQEntry>,
    pub quorum_snapshot_list: Vec<crate::models::snapshot::LLMQSnapshot>,
    pub mn_list_diff_list: Vec<crate::processing::mn_listdiff_result::MNListDiffResult>,
}

impl Default for QRInfoResult {
    fn default() -> Self {
        Self {
            result_at_tip: Default::default(),
            result_at_h: Default::default(),
            result_at_h_c: Default::default(),
            result_at_h_2c: Default::default(),
            result_at_h_3c: Default::default(),
            result_at_h_4c: None,
            snapshot_at_h_c: Default::default(),
            snapshot_at_h_2c: Default::default(),
            snapshot_at_h_3c: Default::default(),
            snapshot_at_h_4c: None,
            extra_share: false,
            last_quorum_per_index: vec![],
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        }
    }
}


// impl<'a, F> TryRead<'a, (Box<dyn CoreProvider>, bool, u32, bool, &mut MasternodeProcessorCache, F)> for QRInfoResult
//     where F: FnMut(models::MNListDiff, bool) -> processing::MNListDiffResult {
// type CONTEXT<'a> = (Box<dyn CoreProvider>, bool, u32, bool, &'a mut MasternodeProcessorCache, Box<dyn FnMut(models::MNListDiff, bool)>);
// impl<'a> TryRead<'a, CONTEXT<'a>> for QRInfoResult {
//     fn try_read(bytes: &'a [u8], ctx: CONTEXT<'a>) -> byte::Result<(Self, usize)> {
//         let provider = ctx.0;
//         let is_from_snapshot = ctx.1;
//         let protocol_version = ctx.2;
//         let is_rotated_quorums_presented = ctx.3;
//         let cache = ctx.4;
//         let mut process_list_diff = ctx.5;
//         let mut offset = &mut 0;
//         // let mut process_list_diff = |list_diff: models::MNListDiff, should_process_quorums: bool| {
//         //     provider(list_diff, should_process_quorums)
//         // };
//         let read_list_diff =
//             |offset: &mut usize|
//                 models::MNListDiff::new(protocol_version, bytes, offset, |block_hash| provider.lookup_block_height_by_hash(block_hash));
//
//         let read_snapshot = |offset: &mut usize| models::LLMQSnapshot::from_bytes(bytes, offset);
//         let read_var_int = |offset: &mut usize| encode::VarInt::from_bytes(bytes, offset);
//         let snapshot_at_h_c = bytes.read_with::<models::LLMQSnapshot>(&mut offset, byte::LE)?;
//         let snapshot_at_h_2c = bytes.read_with::<models::LLMQSnapshot>(&mut offset, byte::LE)?;
//         let snapshot_at_h_3c = bytes.read_with::<models::LLMQSnapshot>(&mut offset, byte::LE)?;
//
//         let diff_tip = read_list_diff(offset)?;
//
//
//         if !is_from_snapshot {
//             provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash).map_err(ProcessingError::from)
//             match provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash) {
//                 Ok(()) => {},
//                 Err(err)
//             }
//             ok_or_return_processing_error!(provider.should_process_diff_with_range(diff_tip.base_block_hash, diff_tip.block_hash));
//         }
//         let diff_h = ok_or_return_processing_error!(read_list_diff(offset));
//         let diff_h_c = ok_or_return_processing_error!(read_list_diff(offset));
//         let diff_h_2c = ok_or_return_processing_error!(read_list_diff(offset));
//         let diff_h_3c = ok_or_return_processing_error!(read_list_diff(offset));
//         let extra_share = bytes.read_with::<bool>(offset, ()).unwrap_or(false);
//         let (snapshot_at_h_4c, diff_h_4c) = if extra_share {
//             let snapshot_at_h_4c = ok_or_return_processing_error!(read_snapshot(offset));
//             let diff_h_4c = ok_or_return_processing_error!(read_list_diff(offset));
//             (Some(snapshot_at_h_4c), Some(diff_h_4c))
//         } else {
//             (None, None)
//         };
//         provider.save_snapshot(diff_h_c.block_hash, snapshot_at_h_c.clone());
//         provider.save_snapshot(diff_h_2c.block_hash, snapshot_at_h_2c.clone());
//         provider.save_snapshot(diff_h_3c.block_hash, snapshot_at_h_3c.clone());
//         if extra_share {
//             provider.save_snapshot(diff_h_4c.as_ref().unwrap().block_hash, snapshot_at_h_4c.clone().unwrap());
//         }
//
//         let last_quorum_per_index_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
//         let mut last_quorum_per_index: Vec<models::LLMQEntry> =
//             Vec::with_capacity(last_quorum_per_index_count);
//         for _i in 0..last_quorum_per_index_count {
//             let quorum = ok_or_return_processing_error!(models::LLMQEntry::from_bytes(bytes, offset));
//             last_quorum_per_index.push(quorum);
//         }
//         let quorum_snapshot_list_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
//         let mut quorum_snapshot_list: Vec<models::LLMQSnapshot> = Vec::with_capacity(quorum_snapshot_list_count);
//         for _i in 0..quorum_snapshot_list_count {
//             let snapshot = ok_or_return_processing_error!(read_snapshot(offset));
//             quorum_snapshot_list.push(snapshot);
//         }
//         let mn_list_diff_list_count = ok_or_return_processing_error!(read_var_int(offset)).0 as usize;
//         let mut mn_list_diff_list: Vec<processing::MNListDiffResult> = Vec::with_capacity(mn_list_diff_list_count);
//         assert_eq!(quorum_snapshot_list_count, mn_list_diff_list_count, "'quorum_snapshot_list_count' must be equal 'mn_list_diff_list_count'");
//         for i in 0..mn_list_diff_list_count {
//             let list_diff = ok_or_return_processing_error!(read_list_diff(offset));
//             let block_hash = list_diff.block_hash;
//             mn_list_diff_list.push(process_list_diff(list_diff, false));
//             provider.save_snapshot(block_hash, quorum_snapshot_list.get(i).unwrap().clone());
//         }
//
//         let result_at_h_4c = if extra_share {
//             Some(process_list_diff(diff_h_4c.unwrap(), false))
//         } else {
//             None
//         };
//
//
//
//         let result_at_h_3c = process_list_diff(diff_h_3c, false);
//         let result_at_h_2c = process_list_diff(diff_h_2c, false);
//         let result_at_h_c = process_list_diff(diff_h_c, false);
//         let result_at_h = process_list_diff(diff_h, true);
//         let result_at_tip = process_list_diff(diff_tip, false);
//
//
//
//
//         // let version = bytes.read_with::<crate::common::LLMQVersion>(offset, LE)?;
//         // let llmq_type = bytes.read_with::<crate::chain::common::LLMQType>(offset, LE)?;
//         // let llmq_hash = bytes.read_with::<UInt256>(offset, LE)?;
//         // let index = if version.use_rotated_quorums() {
//         //     Some(bytes.read_with::<u16>(offset, LE)?)
//         // } else {
//         //     None
//         // };
//         // let signers_count = bytes.read_with::<VarInt>(offset, LE)?;
//         // let signers_buffer_length: usize = ((signers_count.0 as usize) + 7) / 8;
//         // let signers_bitset: &[u8] = bytes.read_with(offset, Bytes::Len(signers_buffer_length))?;
//         // let valid_members_count = bytes.read_with::<VarInt>(offset, LE)?;
//         // let valid_members_count_buffer_length: usize = ((valid_members_count.0 as usize) + 7) / 8;
//         // let valid_members_bitset: &[u8] =
//         //     bytes.read_with(offset, Bytes::Len(valid_members_count_buffer_length))?;
//         // let public_key = bytes.read_with::<UInt384>(offset, LE)?;
//         // let verification_vector_hash = bytes.read_with::<UInt256>(offset, LE)?;
//         // let threshold_signature = bytes.read_with::<UInt768>(offset, LE)?;
//         // let all_commitment_aggregated_signature = bytes.read_with::<UInt768>(offset, LE)?;
//         Ok((QRInfoResult {
//             result_at_tip,
//             result_at_h,
//             result_at_h_c,
//             result_at_h_2c,
//             result_at_h_3c,
//             result_at_h_4c,
//             snapshot_at_h_c,
//             snapshot_at_h_2c,
//             snapshot_at_h_3c,
//             snapshot_at_h_4c,
//             extra_share,
//             last_quorum_per_index,
//             quorum_snapshot_list,
//             mn_list_diff_list
//         }, *offset))
//     }
// }