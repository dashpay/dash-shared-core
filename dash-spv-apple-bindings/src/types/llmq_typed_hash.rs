#[repr(C)]
#[derive(Clone, Debug)]
pub struct LLMQTypedHash {
    pub llmq_type: u8,
    pub llmq_hash: *mut [u8; 32],
}

impl Drop for LLMQTypedHash {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.llmq_hash);
        }
    }
}