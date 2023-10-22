use crate::ffi::unboxer::{unbox_any, unbox_vec_ptr};

#[repr(C)]
#[derive(Clone, Debug)]
pub struct QuorumsCLSigsObject {
    pub signature: *mut [u8; 96],
    pub index_set_count: usize,
    pub index_set: *mut u16,
}

impl Drop for QuorumsCLSigsObject {
    fn drop(&mut self) {
        unsafe {
            unbox_any(self.signature);
            let index_set = unbox_vec_ptr(self.index_set, self.index_set_count);
            drop(index_set);
        }
    }
}