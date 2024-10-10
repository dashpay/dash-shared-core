#[repr(C)]
#[derive(Clone, Debug)]
pub struct LLMQIndexedHash {
    pub index: u32,
    pub hash: *mut [u8; 32],
}

impl Drop for LLMQIndexedHash {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.hash);
        }
    }
}