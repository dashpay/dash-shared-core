#[allow(
    clippy::let_and_return,
    clippy::suspicious_else_formatting,
    clippy::redundant_field_names,
    dead_code,
    redundant_semicolons,
    unused_braces,
    unused_imports,
    unused_unsafe,
    unused_variables,
    unused_qualifications
)]
pub mod types {
    pub mod messages {
        pub mod coinjoin_queue_message {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_queue_message :: CoinJoinQueueMessage\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinQueueMessage {
                pub denomination: u32,
                pub pro_tx_hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                pub time: i64,
                pub ready: bool,
                pub signature: *mut crate::fermented::generics::Vec_u8,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_queue_message::CoinJoinQueueMessage,
                > for CoinJoinQueueMessage
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinQueueMessage,
                ) -> crate::messages::coinjoin_queue_message::CoinJoinQueueMessage {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_queue_message::CoinJoinQueueMessage {
                        denomination: ffi_ref.denomination,
                        pro_tx_hash: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.pro_tx_hash,
                        ),
                        time: ffi_ref.time,
                        ready: ffi_ref.ready,
                        signature: ferment_interfaces::FFIConversion::ffi_from_opt(
                            ffi_ref.signature,
                        ),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_queue_message::CoinJoinQueueMessage,
                ) -> *const CoinJoinQueueMessage {
                    ferment_interfaces::boxed(CoinJoinQueueMessage {
                        denomination: obj.denomination,
                        pro_tx_hash: ferment_interfaces::FFIConversion::ffi_to(obj.pro_tx_hash),
                        time: obj.time,
                        ready: obj.ready,
                        signature: match obj.signature {
                            Some(vec) => ferment_interfaces::FFIConversion::ffi_to(vec),
                            None => std::ptr::null_mut(),
                        },
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinQueueMessage) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinQueueMessage {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.pro_tx_hash);
                        if !ffi_ref.signature.is_null() {
                            ferment_interfaces::unbox_any(ffi_ref.signature);
                        };
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinQueueMessage_ctor(
                denomination: u32,
                pro_tx_hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                time: i64,
                ready: bool,
                signature: *mut crate::fermented::generics::Vec_u8,
            ) -> *mut CoinJoinQueueMessage {
                ferment_interfaces::boxed(CoinJoinQueueMessage {
                    denomination,
                    pro_tx_hash,
                    time,
                    ready,
                    signature,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinQueueMessage_destroy(ffi: *mut CoinJoinQueueMessage) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod transaction_outpoint {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: transaction_outpoint :: TransactionOutPoint\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct TransactionOutPoint {
                pub hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                pub index: u32,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::transaction_outpoint::TransactionOutPoint,
                > for TransactionOutPoint
            {
                unsafe fn ffi_from_const(
                    ffi: *const TransactionOutPoint,
                ) -> crate::messages::transaction_outpoint::TransactionOutPoint {
                    let ffi_ref = &*ffi;
                    crate::messages::transaction_outpoint::TransactionOutPoint {
                        hash: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.hash),
                        index: ffi_ref.index,
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::transaction_outpoint::TransactionOutPoint,
                ) -> *const TransactionOutPoint {
                    ferment_interfaces::boxed(TransactionOutPoint {
                        hash: ferment_interfaces::FFIConversion::ffi_to(obj.hash),
                        index: obj.index,
                    })
                }
                unsafe fn destroy(ffi: *mut TransactionOutPoint) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for TransactionOutPoint {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.hash);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn TransactionOutPoint_ctor(
                hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                index: u32,
            ) -> *mut TransactionOutPoint {
                ferment_interfaces::boxed(TransactionOutPoint { hash, index })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn TransactionOutPoint_destroy(ffi: *mut TransactionOutPoint) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_broadcast_tx {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_broadcast_tx :: CoinJoinBroadcastTx\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinBroadcastTx {
                pub tx: *mut dash_spv_masternode_processor::tx::Transaction,
                pub pro_tx_hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                pub signature: *mut crate::fermented::generics::Vec_u8,
                pub signature_time: i64,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx,
                > for CoinJoinBroadcastTx
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinBroadcastTx,
                ) -> crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx {
                        tx: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.tx),
                        pro_tx_hash: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.pro_tx_hash,
                        ),
                        signature: ferment_interfaces::FFIConversion::ffi_from_opt(
                            ffi_ref.signature,
                        ),
                        signature_time: ffi_ref.signature_time,
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_broadcast_tx::CoinJoinBroadcastTx,
                ) -> *const CoinJoinBroadcastTx {
                    ferment_interfaces::boxed(CoinJoinBroadcastTx {
                        tx: ferment_interfaces::FFIConversion::ffi_to(obj.tx),
                        pro_tx_hash: ferment_interfaces::FFIConversion::ffi_to(obj.pro_tx_hash),
                        signature: match obj.signature {
                            Some(vec) => ferment_interfaces::FFIConversion::ffi_to(vec),
                            None => std::ptr::null_mut(),
                        },
                        signature_time: obj.signature_time,
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinBroadcastTx) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinBroadcastTx {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.tx);
                        ferment_interfaces::unbox_any(ffi_ref.pro_tx_hash);
                        if !ffi_ref.signature.is_null() {
                            ferment_interfaces::unbox_any(ffi_ref.signature);
                        };
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinBroadcastTx_ctor(
                tx: *mut dash_spv_masternode_processor::tx::Transaction,
                pro_tx_hash: *mut dash_spv_masternode_processor::crypto::UInt256,
                signature: *mut crate::fermented::generics::Vec_u8,
                signature_time: i64,
            ) -> *mut CoinJoinBroadcastTx {
                ferment_interfaces::boxed(CoinJoinBroadcastTx {
                    tx,
                    pro_tx_hash,
                    signature,
                    signature_time,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinBroadcastTx_destroy(ffi: *mut CoinJoinBroadcastTx) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_entry {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_entry :: CoinJoinEntry\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinEntry { pub mixing_inputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionInput , pub mixing_outputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionOutput , pub tx_collateral : * mut dash_spv_masternode_processor :: tx :: Transaction , }
            impl ferment_interfaces::FFIConversion<crate::messages::coinjoin_entry::CoinJoinEntry>
                for CoinJoinEntry
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinEntry,
                ) -> crate::messages::coinjoin_entry::CoinJoinEntry {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_entry::CoinJoinEntry {
                        mixing_inputs: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.mixing_inputs,
                        ),
                        mixing_outputs: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.mixing_outputs,
                        ),
                        tx_collateral: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.tx_collateral,
                        ),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_entry::CoinJoinEntry,
                ) -> *const CoinJoinEntry {
                    ferment_interfaces::boxed(CoinJoinEntry {
                        mixing_inputs: ferment_interfaces::FFIConversion::ffi_to(obj.mixing_inputs),
                        mixing_outputs: ferment_interfaces::FFIConversion::ffi_to(
                            obj.mixing_outputs,
                        ),
                        tx_collateral: ferment_interfaces::FFIConversion::ffi_to(obj.tx_collateral),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinEntry) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinEntry {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.mixing_inputs);
                        ferment_interfaces::unbox_any(ffi_ref.mixing_outputs);
                        ferment_interfaces::unbox_any(ffi_ref.tx_collateral);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinEntry_ctor(
                mixing_inputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionInput,
                mixing_outputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionOutput,
                tx_collateral: *mut dash_spv_masternode_processor::tx::Transaction,
            ) -> *mut CoinJoinEntry {
                ferment_interfaces::boxed(CoinJoinEntry {
                    mixing_inputs,
                    mixing_outputs,
                    tx_collateral,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinEntry_destroy(ffi: *mut CoinJoinEntry) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_final_transaction {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_final_transaction :: CoinJoinFinalTransaction\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinFinalTransaction {
                pub msg_session_id: i32,
                pub tx: *mut dash_spv_masternode_processor::tx::Transaction,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_final_transaction::CoinJoinFinalTransaction,
                > for CoinJoinFinalTransaction
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinFinalTransaction,
                ) -> crate::messages::coinjoin_final_transaction::CoinJoinFinalTransaction
                {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_final_transaction::CoinJoinFinalTransaction {
                        msg_session_id: ffi_ref.msg_session_id,
                        tx: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.tx),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_final_transaction::CoinJoinFinalTransaction,
                ) -> *const CoinJoinFinalTransaction {
                    ferment_interfaces::boxed(CoinJoinFinalTransaction {
                        msg_session_id: obj.msg_session_id,
                        tx: ferment_interfaces::FFIConversion::ffi_to(obj.tx),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinFinalTransaction) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinFinalTransaction {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.tx);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinFinalTransaction_ctor(
                msg_session_id: i32,
                tx: *mut dash_spv_masternode_processor::tx::Transaction,
            ) -> *mut CoinJoinFinalTransaction {
                ferment_interfaces::boxed(CoinJoinFinalTransaction { msg_session_id, tx })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinFinalTransaction_destroy(
                ffi: *mut CoinJoinFinalTransaction,
            ) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod send_coinjoin_queue {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: send_coinjoin_queue :: SendCoinJoinQueue\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct SendCoinJoinQueue {
                pub send: bool,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::send_coinjoin_queue::SendCoinJoinQueue,
                > for SendCoinJoinQueue
            {
                unsafe fn ffi_from_const(
                    ffi: *const SendCoinJoinQueue,
                ) -> crate::messages::send_coinjoin_queue::SendCoinJoinQueue {
                    let ffi_ref = &*ffi;
                    crate::messages::send_coinjoin_queue::SendCoinJoinQueue { send: ffi_ref.send }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::send_coinjoin_queue::SendCoinJoinQueue,
                ) -> *const SendCoinJoinQueue {
                    ferment_interfaces::boxed(SendCoinJoinQueue { send: obj.send })
                }
                unsafe fn destroy(ffi: *mut SendCoinJoinQueue) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for SendCoinJoinQueue {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn SendCoinJoinQueue_ctor(send: bool) -> *mut SendCoinJoinQueue {
                ferment_interfaces::boxed(SendCoinJoinQueue { send })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn SendCoinJoinQueue_destroy(ffi: *mut SendCoinJoinQueue) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_status_update {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_status_update :: CoinJoinStatusUpdate\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinStatusUpdate {
                pub session_id: i32,
                pub pool_state: *mut super::pool_state::PoolState,
                pub status_update: *mut super::pool_status_update::PoolStatusUpdate,
                pub message_id: *mut super::pool_message::PoolMessage,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_status_update::CoinJoinStatusUpdate,
                > for CoinJoinStatusUpdate
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinStatusUpdate,
                ) -> crate::messages::coinjoin_status_update::CoinJoinStatusUpdate {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_status_update::CoinJoinStatusUpdate {
                        session_id: ffi_ref.session_id,
                        pool_state: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.pool_state),
                        status_update: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.status_update,
                        ),
                        message_id: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.message_id),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_status_update::CoinJoinStatusUpdate,
                ) -> *const CoinJoinStatusUpdate {
                    ferment_interfaces::boxed(CoinJoinStatusUpdate {
                        session_id: obj.session_id,
                        pool_state: ferment_interfaces::FFIConversion::ffi_to(obj.pool_state),
                        status_update: ferment_interfaces::FFIConversion::ffi_to(obj.status_update),
                        message_id: ferment_interfaces::FFIConversion::ffi_to(obj.message_id),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinStatusUpdate) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinStatusUpdate {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.pool_state);
                        ferment_interfaces::unbox_any(ffi_ref.status_update);
                        ferment_interfaces::unbox_any(ffi_ref.message_id);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinStatusUpdate_ctor(
                session_id: i32,
                pool_state: *mut super::pool_state::PoolState,
                status_update: *mut super::pool_status_update::PoolStatusUpdate,
                message_id: *mut super::pool_message::PoolMessage,
            ) -> *mut CoinJoinStatusUpdate {
                ferment_interfaces::boxed(CoinJoinStatusUpdate {
                    session_id,
                    pool_state,
                    status_update,
                    message_id,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinStatusUpdate_destroy(ffi: *mut CoinJoinStatusUpdate) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_accept_message {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_accept_message :: CoinJoinAcceptMessage\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinAcceptMessage {
                pub denomination: u32,
                pub tx_collateral: *mut dash_spv_masternode_processor::tx::Transaction,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_accept_message::CoinJoinAcceptMessage,
                > for CoinJoinAcceptMessage
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinAcceptMessage,
                ) -> crate::messages::coinjoin_accept_message::CoinJoinAcceptMessage
                {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_accept_message::CoinJoinAcceptMessage {
                        denomination: ffi_ref.denomination,
                        tx_collateral: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.tx_collateral,
                        ),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_accept_message::CoinJoinAcceptMessage,
                ) -> *const CoinJoinAcceptMessage {
                    ferment_interfaces::boxed(CoinJoinAcceptMessage {
                        denomination: obj.denomination,
                        tx_collateral: ferment_interfaces::FFIConversion::ffi_to(obj.tx_collateral),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinAcceptMessage) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinAcceptMessage {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.tx_collateral);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinAcceptMessage_ctor(
                denomination: u32,
                tx_collateral: *mut dash_spv_masternode_processor::tx::Transaction,
            ) -> *mut CoinJoinAcceptMessage {
                ferment_interfaces::boxed(CoinJoinAcceptMessage {
                    denomination,
                    tx_collateral,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinAcceptMessage_destroy(
                ffi: *mut CoinJoinAcceptMessage,
            ) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_complete_message {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_complete_message :: CoinJoinCompleteMessage\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinCompleteMessage {
                pub msg_session_id: i32,
                pub msg_message_id: *mut super::pool_message::PoolMessage,
            }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_complete_message::CoinJoinCompleteMessage,
                > for CoinJoinCompleteMessage
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinCompleteMessage,
                ) -> crate::messages::coinjoin_complete_message::CoinJoinCompleteMessage
                {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_complete_message::CoinJoinCompleteMessage {
                        msg_session_id: ffi_ref.msg_session_id,
                        msg_message_id: ferment_interfaces::FFIConversion::ffi_from(
                            ffi_ref.msg_message_id,
                        ),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_complete_message::CoinJoinCompleteMessage,
                ) -> *const CoinJoinCompleteMessage {
                    ferment_interfaces::boxed(CoinJoinCompleteMessage {
                        msg_session_id: obj.msg_session_id,
                        msg_message_id: ferment_interfaces::FFIConversion::ffi_to(
                            obj.msg_message_id,
                        ),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinCompleteMessage) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinCompleteMessage {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.msg_message_id);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinCompleteMessage_ctor(
                msg_session_id: i32,
                msg_message_id: *mut super::pool_message::PoolMessage,
            ) -> *mut CoinJoinCompleteMessage {
                ferment_interfaces::boxed(CoinJoinCompleteMessage {
                    msg_session_id,
                    msg_message_id,
                })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinCompleteMessage_destroy(
                ffi: *mut CoinJoinCompleteMessage,
            ) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
        pub mod coinjoin_signed_inputs {
            #[doc = "FFI-representation of the # [doc = \"FFI-representation of the crate :: messages :: coinjoin_signed_inputs :: CoinJoinSignedInputs\"]"]
            #[repr(C)]
            #[derive(Clone)]
            #[allow(non_camel_case_types)]
            pub struct CoinJoinSignedInputs { pub inputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionInput , }
            impl
                ferment_interfaces::FFIConversion<
                    crate::messages::coinjoin_signed_inputs::CoinJoinSignedInputs,
                > for CoinJoinSignedInputs
            {
                unsafe fn ffi_from_const(
                    ffi: *const CoinJoinSignedInputs,
                ) -> crate::messages::coinjoin_signed_inputs::CoinJoinSignedInputs {
                    let ffi_ref = &*ffi;
                    crate::messages::coinjoin_signed_inputs::CoinJoinSignedInputs {
                        inputs: ferment_interfaces::FFIConversion::ffi_from(ffi_ref.inputs),
                    }
                }
                unsafe fn ffi_to_const(
                    obj: crate::messages::coinjoin_signed_inputs::CoinJoinSignedInputs,
                ) -> *const CoinJoinSignedInputs {
                    ferment_interfaces::boxed(CoinJoinSignedInputs {
                        inputs: ferment_interfaces::FFIConversion::ffi_to(obj.inputs),
                    })
                }
                unsafe fn destroy(ffi: *mut CoinJoinSignedInputs) {
                    ferment_interfaces::unbox_any(ffi);
                }
            }
            impl Drop for CoinJoinSignedInputs {
                fn drop(&mut self) {
                    unsafe {
                        let ffi_ref = self;
                        ferment_interfaces::unbox_any(ffi_ref.inputs);
                    }
                }
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinSignedInputs_ctor(
                inputs : * mut crate :: fermented :: generics :: Vec_dash_spv_masternode_processor_tx_TransactionInput,
            ) -> *mut CoinJoinSignedInputs {
                ferment_interfaces::boxed(CoinJoinSignedInputs { inputs })
            }
            #[doc = r" # Safety"]
            #[allow(non_snake_case)]
            #[no_mangle]
            pub unsafe extern "C" fn CoinJoinSignedInputs_destroy(ffi: *mut CoinJoinSignedInputs) {
                ferment_interfaces::unbox_any(ffi);
            }
        }
    }
}
#[allow(
    clippy::let_and_return,
    clippy::suspicious_else_formatting,
    clippy::redundant_field_names,
    dead_code,
    redundant_semicolons,
    unused_braces,
    unused_imports,
    unused_unsafe,
    unused_variables,
    unused_qualifications
)]
pub mod generics {
    #[repr(C)]
    #[derive(Clone)]
    #[allow(non_camel_case_types)]
    pub struct Vec_dash_spv_masternode_processor_tx_TransactionOutput {
        pub count: usize,
        pub values:
            *mut *mut crate::fermented::types::dash_spv_masternode_processor::tx::TransactionOutput,
    }
    impl
        ferment_interfaces::FFIConversion<Vec<dash_spv_masternode_processor::tx::TransactionOutput>>
        for Vec_dash_spv_masternode_processor_tx_TransactionOutput
    {
        unsafe fn ffi_from_const(
            ffi: *const Vec_dash_spv_masternode_processor_tx_TransactionOutput,
        ) -> Vec<dash_spv_masternode_processor::tx::TransactionOutput> {
            ferment_interfaces::FFIVecConversion::decode(&*ffi)
        }
        unsafe fn ffi_to_const(
            obj: Vec<dash_spv_masternode_processor::tx::TransactionOutput>,
        ) -> *const Vec_dash_spv_masternode_processor_tx_TransactionOutput {
            ferment_interfaces::FFIVecConversion::encode(obj)
        }
        unsafe fn destroy(ffi: *mut Vec_dash_spv_masternode_processor_tx_TransactionOutput) {
            ferment_interfaces::unbox_any(ffi);
        }
    }
    impl ferment_interfaces::FFIVecConversion
        for Vec_dash_spv_masternode_processor_tx_TransactionOutput
    {
        type Value = Vec<dash_spv_masternode_processor::tx::TransactionOutput>;
        unsafe fn decode(&self) -> Self::Value {
            ferment_interfaces::from_complex_vec(self.values, self.count)
        }
        unsafe fn encode(obj: Self::Value) -> *mut Self {
            ferment_interfaces::boxed(Self {
                count: obj.len(),
                values: ferment_interfaces::to_complex_vec(obj.into_iter()),
            })
        }
    }
    impl Drop for Vec_dash_spv_masternode_processor_tx_TransactionOutput {
        fn drop(&mut self) {
            unsafe {
                ferment_interfaces::unbox_any_vec_ptr(self.values, self.count);
            }
        }
    }
    #[repr(C)]
    #[derive(Clone)]
    #[allow(non_camel_case_types)]
    pub struct Vec_dash_spv_masternode_processor_tx_TransactionInput {
        pub count: usize,
        pub values:
            *mut *mut crate::fermented::types::dash_spv_masternode_processor::tx::TransactionInput,
    }
    impl ferment_interfaces::FFIConversion<Vec<dash_spv_masternode_processor::tx::TransactionInput>>
        for Vec_dash_spv_masternode_processor_tx_TransactionInput
    {
        unsafe fn ffi_from_const(
            ffi: *const Vec_dash_spv_masternode_processor_tx_TransactionInput,
        ) -> Vec<dash_spv_masternode_processor::tx::TransactionInput> {
            ferment_interfaces::FFIVecConversion::decode(&*ffi)
        }
        unsafe fn ffi_to_const(
            obj: Vec<dash_spv_masternode_processor::tx::TransactionInput>,
        ) -> *const Vec_dash_spv_masternode_processor_tx_TransactionInput {
            ferment_interfaces::FFIVecConversion::encode(obj)
        }
        unsafe fn destroy(ffi: *mut Vec_dash_spv_masternode_processor_tx_TransactionInput) {
            ferment_interfaces::unbox_any(ffi);
        }
    }
    impl ferment_interfaces::FFIVecConversion
        for Vec_dash_spv_masternode_processor_tx_TransactionInput
    {
        type Value = Vec<dash_spv_masternode_processor::tx::TransactionInput>;
        unsafe fn decode(&self) -> Self::Value {
            ferment_interfaces::from_complex_vec(self.values, self.count)
        }
        unsafe fn encode(obj: Self::Value) -> *mut Self {
            ferment_interfaces::boxed(Self {
                count: obj.len(),
                values: ferment_interfaces::to_complex_vec(obj.into_iter()),
            })
        }
    }
    impl Drop for Vec_dash_spv_masternode_processor_tx_TransactionInput {
        fn drop(&mut self) {
            unsafe {
                ferment_interfaces::unbox_any_vec_ptr(self.values, self.count);
            }
        }
    }
    #[repr(C)]
    #[derive(Clone)]
    #[allow(non_camel_case_types)]
    pub struct Vec_u8 {
        pub count: usize,
        pub values: *mut u8,
    }
    impl ferment_interfaces::FFIConversion<Vec<u8>> for Vec_u8 {
        unsafe fn ffi_from_const(ffi: *const Vec_u8) -> Vec<u8> {
            ferment_interfaces::FFIVecConversion::decode(&*ffi)
        }
        unsafe fn ffi_to_const(obj: Vec<u8>) -> *const Vec_u8 {
            ferment_interfaces::FFIVecConversion::encode(obj)
        }
        unsafe fn destroy(ffi: *mut Vec_u8) {
            ferment_interfaces::unbox_any(ffi);
        }
    }
    impl ferment_interfaces::FFIVecConversion for Vec_u8 {
        type Value = Vec<u8>;
        unsafe fn decode(&self) -> Self::Value {
            ferment_interfaces::from_primitive_vec(self.values, self.count)
        }
        unsafe fn encode(obj: Self::Value) -> *mut Self {
            ferment_interfaces::boxed(Self {
                count: obj.len(),
                values: ferment_interfaces::boxed_vec(obj),
            })
        }
    }
    impl Drop for Vec_u8 {
        fn drop(&mut self) {
            unsafe {
                ferment_interfaces::unbox_vec_ptr(self.values, self.count);
            }
        }
    }
}
