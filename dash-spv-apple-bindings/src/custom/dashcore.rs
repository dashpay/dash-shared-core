use dashcore::hashes::Hash;
// use dashcore::secp256k1::ThirtyTwoByteHash;

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::OutPoint)]
#[derive(Clone)]
pub struct OutPoint {
    pub txid: *mut [u8; 32],
    pub vout: u32,
}
impl ferment::FFIConversionFrom<dashcore::OutPoint> for OutPoint {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::OutPoint {
        let ffi = &*ffi;
        dashcore::OutPoint::new(dashcore::hash_types::Txid::from_slice(&*ffi.txid).expect("err"), ffi.vout)
    }
}
impl ferment::FFIConversionTo<dashcore::OutPoint> for OutPoint {
    unsafe fn ffi_to_const(obj: dashcore::OutPoint) -> *const Self {
        ferment::boxed(OutPoint { txid: ferment::boxed(obj.txid.to_raw_hash().into()), vout: obj.vout })
    }
}

impl Drop for OutPoint {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.txid);
        }
    }
}

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::InstantLock)]
#[derive(Clone)]
pub struct InstantLock {
    pub raw: *mut dashcore::InstantLock,
}
impl ferment::FFIConversionFrom<dashcore::InstantLock> for InstantLock {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::InstantLock {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment::FFIConversionTo<dashcore::InstantLock> for InstantLock {
    unsafe fn ffi_to_const(obj: dashcore::InstantLock) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj) })
    }
}

impl Drop for InstantLock {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::Transaction)]
#[derive(Clone)]
pub struct Transaction {
    pub raw: *mut dashcore::Transaction,
}
impl ferment::FFIConversionFrom<dashcore::Transaction> for Transaction {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::Transaction {
        let ffi = &*ffi;
        let raw = &*ffi.raw;
        raw.clone()
    }
}
impl ferment::FFIConversionTo<dashcore::Transaction> for Transaction {
    unsafe fn ffi_to_const(obj: dashcore::Transaction) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj) })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}

#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::consensus::encode::Error)]
pub struct dashcore_consensus_Error {
    pub raw: *mut dashcore::consensus::encode::Error,
}

impl ferment::FFIConversionFrom<dashcore::consensus::encode::Error> for dashcore_consensus_Error {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::consensus::encode::Error {
        *ferment::unbox_any((&*ffi).raw)
    }
}
impl ferment::FFIConversionTo<dashcore::consensus::encode::Error> for dashcore_consensus_Error {
    unsafe fn ffi_to_const(obj: dashcore::consensus::encode::Error) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj.into()) })
    }
}

impl Drop for dashcore_consensus_Error {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}


#[allow(non_camel_case_types)]
#[ferment_macro::register(dashcore::Txid)]
pub struct dashcore_Txid {
    pub raw: *mut [u8; 32],
}

impl ferment::FFIConversionFrom<dashcore::Txid> for dashcore_Txid {
    unsafe fn ffi_from_const(ffi: *const Self) -> dashcore::Txid {
        let ffi_ref = &*ffi;
        dashcore::Txid::from_slice(&*ffi_ref.raw)
            .expect("TxId error")
    }
}
impl ferment::FFIConversionTo<dashcore::Txid> for dashcore_Txid {
    unsafe fn ffi_to_const(obj: dashcore::Txid) -> *const Self {
        ferment::boxed(Self { raw: ferment::boxed(obj.into()) })
    }
}

impl Drop for dashcore_Txid {
    fn drop(&mut self) {
        unsafe {
            ferment::unbox_any(self.raw);
        }
    }
}
