#[repr(C)]
#[derive(Clone, Debug)]
pub struct Block {
    pub height: u32,
    pub hash: *mut [u8; 32],
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe {
            ferment_interfaces::unbox_any(self.hash);
        }
    }
}