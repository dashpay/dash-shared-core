use crate::types::llmq_entry::LLMQEntry;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct LLMQMap {
    pub llmq_type: u8,
    pub values: *mut *mut LLMQEntry,
    pub count: usize,
}

impl Drop for LLMQMap {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any_vec_ptr(self.values, self.count);
        }
    }
}