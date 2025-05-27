use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct FFIThreadSafeContext {
    pub inner: Arc<Mutex<*const std::ffi::c_void>>
}
unsafe impl Send for FFIThreadSafeContext {}
unsafe impl Sync for FFIThreadSafeContext {}

#[ferment_macro::export]
impl FFIThreadSafeContext {
    pub fn new(context: *const std::ffi::c_void) -> Self {
        FFIThreadSafeContext {
            inner: Arc::new(Mutex::new(context)),
        }
    }
}

impl FFIThreadSafeContext {
    pub fn get(&self) -> *const std::ffi::c_void {
        let lock = self.inner.lock().unwrap();
        *lock
    }

    pub fn set(&self, new_context: *const std::ffi::c_void) {
        let mut lock = self.inner.lock().unwrap();
        *lock = new_context;
    }
}

