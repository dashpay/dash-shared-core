use crate::models::snapshot::LLMQSnapshot;
use crate::processing::mn_listdiff_result::MNListDiffResult;

#[derive(Clone, Debug)]
#[ferment_macro::export]
pub struct QRInfoResult {

    pub result_at_tip: MNListDiffResult,
    pub result_at_h: MNListDiffResult,
    pub result_at_h_c: MNListDiffResult,
    pub result_at_h_2c: MNListDiffResult,
    pub result_at_h_3c: MNListDiffResult,
    pub result_at_h_4c: Option<MNListDiffResult>,

    // pub snapshot_at_h_c: LLMQSnapshot,
    // pub snapshot_at_h_2c: LLMQSnapshot,
    // pub snapshot_at_h_3c: LLMQSnapshot,
    // pub snapshot_at_h_4c: Option<LLMQSnapshot>,

    // pub extra_share: bool,
    // pub last_quorum_per_index: Vec<LLMQEntry>,
    pub quorum_snapshot_list: Vec<LLMQSnapshot>,
    pub mn_list_diff_list: Vec<MNListDiffResult>,
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
            // snapshot_at_h_c: Default::default(),
            // snapshot_at_h_2c: Default::default(),
            // snapshot_at_h_3c: Default::default(),
            // snapshot_at_h_4c: None,
            // extra_share: false,
            // last_quorum_per_index: vec![],
            quorum_snapshot_list: vec![],
            mn_list_diff_list: vec![],
        }
    }
}
