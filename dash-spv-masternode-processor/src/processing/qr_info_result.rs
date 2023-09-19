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
