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
            let ffi_ref = self;
            rs_ffi_interfaces::unbox_any(ffi_ref.signature);
            let index_set = rs_ffi_interfaces::unbox_vec_ptr(ffi_ref.index_set, ffi_ref.index_set_count);
            drop(index_set);
        }
    }
}
