pub struct MNListDiffResult
{
    pub error_status : crate :: processing :: processing_error ::
    ProcessingError, pub base_block_hash : UInt256, pub block_hash : UInt256,
    pub has_found_coinbase : bool, pub has_valid_coinbase : bool, pub
    has_valid_mn_list_root : bool, pub has_valid_llmq_list_root : bool, pub
    has_valid_quorums : bool, pub masternode_list : crate :: models ::
    masternode_list :: MasternodeList, pub added_masternodes : BTreeMap <
    UInt256, crate :: models :: masternode_entry :: MasternodeEntry >, pub
    modified_masternodes : BTreeMap < UInt256, crate :: models ::
    masternode_entry :: MasternodeEntry >, pub added_quorums : BTreeMap <
    crate :: chain :: common :: llmq_type :: LLMQType, BTreeMap < UInt256,
    crate :: models :: llmq_entry :: LLMQEntry >, >, pub
    needed_masternode_lists : Vec < UInt256 >, pub quorums_cl_sigs : Vec <
    crate :: models :: quorums_cl_sigs_object :: QuorumsCLSigsObject >,
} #[doc = "FFI-representation of the"] #[doc = "MNListDiffResult"] #[repr(C)]
#[derive(Clone, Debug)] pub struct MNListDiffResultFFI
{
    pub error_status : * mut crate :: processing :: processing_error ::
    ProcessingErrorFFI, pub base_block_hash : * mut [u8 ; 32], pub block_hash
    : * mut [u8 ; 32], pub has_found_coinbase : bool, pub has_valid_coinbase :
    bool, pub has_valid_mn_list_root : bool, pub has_valid_llmq_list_root :
    bool, pub has_valid_quorums : bool, pub masternode_list : * mut crate ::
    models :: masternode_list :: MasternodeListFFI, pub added_masternodes : *
    mut rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut crate :: models
    :: masternode_entry :: MasternodeEntryFFI >, pub modified_masternodes : *
    mut rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut crate :: models
    :: masternode_entry :: MasternodeEntryFFI >, pub added_quorums : * mut
    rs_ffi_interfaces :: MapFFI < * mut crate :: chain :: common :: llmq_type
    :: LLMQTypeFFI, * mut rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut
    crate :: models :: llmq_entry :: LLMQEntryFFI > >, pub
    needed_masternode_lists : * mut rs_ffi_interfaces :: VecFFI < * mut
    [u8 ; 32] >, pub quorums_cl_sigs : * mut rs_ffi_interfaces :: VecFFI < *
    mut crate :: models :: quorums_cl_sigs_object :: QuorumsCLSigsObjectFFI >,
} impl rs_ffi_interfaces :: FFIConversion < MNListDiffResult > for
MNListDiffResultFFI
{
    unsafe fn ffi_from(ffi : * mut MNListDiffResultFFI) -> MNListDiffResult
    {
        let ffi_ref = & * ffi ; MNListDiffResult
        {
            error_status : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.error_status), base_block_hash :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.base_block_hash), block_hash : rs_ffi_interfaces
            :: FFIConversion :: ffi_from(ffi_ref.block_hash),
            has_found_coinbase : ffi_ref.has_found_coinbase,
            has_valid_coinbase : ffi_ref.has_valid_coinbase,
            has_valid_mn_list_root : ffi_ref.has_valid_mn_list_root,
            has_valid_llmq_list_root : ffi_ref.has_valid_llmq_list_root,
            has_valid_quorums : ffi_ref.has_valid_quorums, masternode_list :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.masternode_list), added_masternodes :
            {
                let map = & * ffi_ref.added_masternodes ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, modified_masternodes :
            {
                let map = & * ffi_ref.modified_masternodes ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, added_quorums :
            {
                let map = & * ffi_ref.added_quorums ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = rs_ffi_interfaces :: FFIConversion ::
                            ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                            :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                            acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, needed_masternode_lists :
            {
                let vec = & * ffi_ref.needed_masternode_lists ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }, quorums_cl_sigs :
            {
                let vec = & * ffi_ref.quorums_cl_sigs ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            },
        }
    } unsafe fn ffi_to(obj : MNListDiffResult) -> * mut MNListDiffResultFFI
    {
        rs_ffi_interfaces ::
        boxed(MNListDiffResultFFI
        {
            error_status : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.error_status), base_block_hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.base_block_hash), block_hash :
            rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.block_hash),
            has_found_coinbase : obj.has_found_coinbase, has_valid_coinbase :
            obj.has_valid_coinbase, has_valid_mn_list_root :
            obj.has_valid_mn_list_root, has_valid_llmq_list_root :
            obj.has_valid_llmq_list_root, has_valid_quorums :
            obj.has_valid_quorums, masternode_list : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.masternode_list), added_masternodes :
            rs_ffi_interfaces ::
            boxed({
                let map = obj.added_masternodes ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), modified_masternodes : rs_ffi_interfaces ::
            boxed({
                let map = obj.modified_masternodes ; rs_ffi_interfaces ::
                MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), added_quorums : rs_ffi_interfaces ::
            boxed({
                let map = obj.added_quorums ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                            FFIConversion :: ffi_to(o)).collect()), values :
                            rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            :: FFIConversion :: ffi_to(o)).collect())
                        }
                    })).collect())
                }
            }), needed_masternode_lists : rs_ffi_interfaces ::
            boxed({
                let vec = obj.needed_masternode_lists ; rs_ffi_interfaces ::
                VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }), quorums_cl_sigs : rs_ffi_interfaces ::
            boxed({
                let vec = obj.quorums_cl_sigs ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }),
        })
    } unsafe fn destroy(ffi : * mut MNListDiffResultFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for MNListDiffResultFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < crate :: processing :: processing_error ::
            ProcessingErrorFFI as rs_ffi_interfaces :: FFIConversion < crate
            :: processing :: processing_error :: ProcessingError >> ::
            destroy(ffi_ref.error_status) ; < [u8 ; 32] as rs_ffi_interfaces
            :: FFIConversion < UInt256 >> :: destroy(ffi_ref.base_block_hash)
            ; < [u8 ; 32] as rs_ffi_interfaces :: FFIConversion < UInt256 >>
            :: destroy(ffi_ref.block_hash) ; {} ; {} ; {} ; {} ; {} ; < crate
            :: models :: masternode_list :: MasternodeListFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: models ::
            masternode_list :: MasternodeList >> ::
            destroy(ffi_ref.masternode_list) ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.added_masternodes) ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.modified_masternodes) ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.added_quorums) ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.needed_masternode_lists) ; ; rs_ffi_interfaces
            :: unbox_any(ffi_ref.quorums_cl_sigs) ; ;
        }
    }
}
pub enum TestEnum
{
    Variant1(String), Variant2, Variant3(UInt256, u32),
    Variant4(UInt256, u32, String),
} #[doc = "FFI-representation of the"] #[doc = "TestEnum"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
TestEnumFFI
{
    Variant1(* mut std :: os :: raw :: c_char), Variant2,
    Variant3(* mut [u8 ; 32], u32),
    Variant4(* mut [u8 ; 32], u32, * mut std :: os :: raw :: c_char),
} impl rs_ffi_interfaces :: FFIConversion < TestEnum > for TestEnumFFI
{
    unsafe fn ffi_from(ffi : * mut TestEnumFFI) -> TestEnum
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            TestEnumFFI :: Variant1(o_0,) => TestEnum ::
            Variant1(rs_ffi_interfaces :: FFIConversion :: ffi_from(* o_0),),
            TestEnumFFI :: Variant2 => TestEnum :: Variant2, TestEnumFFI ::
            Variant3(o_0, o_1,) => TestEnum ::
            Variant3(rs_ffi_interfaces :: FFIConversion :: ffi_from(* o_0), *
            o_1,), TestEnumFFI :: Variant4(o_0, o_1, o_2,) => TestEnum ::
            Variant4(rs_ffi_interfaces :: FFIConversion :: ffi_from(* o_0), *
            o_1, rs_ffi_interfaces :: FFIConversion :: ffi_from(* o_2),)
        }
    } unsafe fn ffi_to(obj : TestEnum) -> * mut TestEnumFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            TestEnum :: Variant1(o_0,) => TestEnumFFI ::
            Variant1(rs_ffi_interfaces :: FFIConversion :: ffi_to(o_0),),
            TestEnum :: Variant2 => TestEnumFFI :: Variant2, TestEnum ::
            Variant3(o_0, o_1,) => TestEnumFFI ::
            Variant3(rs_ffi_interfaces :: FFIConversion :: ffi_to(o_0), o_1,),
            TestEnum :: Variant4(o_0, o_1, o_2,) => TestEnumFFI ::
            Variant4(rs_ffi_interfaces :: FFIConversion :: ffi_to(o_0), o_1,
            rs_ffi_interfaces :: FFIConversion :: ffi_to(o_2),)
        })
    } unsafe fn destroy(ffi : * mut TestEnumFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TestEnumFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                TestEnumFFI :: Variant1(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                TestEnumFFI :: Variant2 => {}, TestEnumFFI ::
                Variant3(o_0, o_1,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                TestEnumFFI :: Variant4(o_0, o_1, o_2,) =>
                {
                    let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; let o_2 =
                    rs_ffi_interfaces :: unbox_any(o_2) ;
                },
            }
        }
    }
}
pub type KeyID = u32 ; #[doc = "FFI-representation of the"] #[doc = "KeyID"]
#[repr(C)] #[derive(Clone, Debug)] pub struct KeyIDFFI(u32) ; impl
rs_ffi_interfaces :: FFIConversion < KeyID > for KeyIDFFI
{
    unsafe fn ffi_from(ffi : * mut KeyIDFFI) -> KeyID
    { let ffi_ref = & * ffi ; ffi_ref.0 } unsafe fn ffi_to(obj : KeyID) -> *
    mut KeyIDFFI { rs_ffi_interfaces :: boxed(KeyIDFFI(obj)) } unsafe fn
    destroy(ffi : * mut KeyIDFFI) { rs_ffi_interfaces :: unbox_any(ffi) ; }
}
pub type HashID = [u8 ; 32] ; #[doc = "FFI-representation of the"]
#[doc = "HashID"] #[repr(C)] #[derive(Clone, Debug)] pub struct
HashIDFFI(* mut [u8 ; 32]) ; impl rs_ffi_interfaces :: FFIConversion < HashID
> for HashIDFFI
{
    unsafe fn ffi_from(ffi : * mut HashIDFFI) -> HashID
    { let ffi_ref = & * ffi ; * ffi_ref.0 } unsafe fn ffi_to(obj : HashID) ->
    * mut HashIDFFI
    { rs_ffi_interfaces :: boxed(HashIDFFI(rs_ffi_interfaces :: boxed(obj))) }
    unsafe fn destroy(ffi : * mut HashIDFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for HashIDFFI
{
    fn drop(& mut self)
    { unsafe { rs_ffi_interfaces :: unbox_any(self.0) ; } }
}
pub type UsedKeyMatrix = Vec < bool > ; #[doc = "FFI-representation of the"]
#[doc = "UsedKeyMatrix"] #[repr(C)] #[derive(Clone, Debug)] pub struct
UsedKeyMatrixFFI(* mut rs_ffi_interfaces :: VecFFI < bool >) ; impl
rs_ffi_interfaces :: FFIConversion < UsedKeyMatrix > for UsedKeyMatrixFFI
{
    unsafe fn ffi_from(ffi : * mut UsedKeyMatrixFFI) -> UsedKeyMatrix
    {
        {
            let vec = & * (& * ffi).0 ; std :: slice ::
            from_raw_parts(vec.values as * const bool, vec.count).to_vec()
        }
    } unsafe fn ffi_to(obj : UsedKeyMatrix) -> * mut UsedKeyMatrixFFI
    {
        rs_ffi_interfaces ::
        boxed(UsedKeyMatrixFFI(rs_ffi_interfaces ::
        boxed({
            let vec = obj ; rs_ffi_interfaces :: VecFFI
            {
                count : vec.len(), values : rs_ffi_interfaces ::
                boxed_vec(vec.clone())
            }
        })))
    } unsafe fn destroy(ffi : * mut UsedKeyMatrixFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for UsedKeyMatrixFFI
{
    fn drop(& mut self)
    { unsafe { rs_ffi_interfaces :: unbox_any(self.0) ; } }
}
pub type ArrayOfArraysOfHashes = Vec < Vec < UInt256 > > ;
#[doc = "FFI-representation of the"] #[doc = "ArrayOfArraysOfHashes"]
#[repr(C)] #[derive(Clone, Debug)] pub struct
ArrayOfArraysOfHashesFFI(* mut rs_ffi_interfaces :: VecFFI < * mut
rs_ffi_interfaces :: VecFFI < * mut [u8 ; 32] > >) ; impl rs_ffi_interfaces ::
FFIConversion < ArrayOfArraysOfHashes > for ArrayOfArraysOfHashesFFI
{
    unsafe fn ffi_from(ffi : * mut ArrayOfArraysOfHashesFFI) ->
    ArrayOfArraysOfHashes
    {
        {
            let vec = & * (& * ffi).0 ;
            (0 ..
            vec.count).map(| i |
            {
                let vec = & * * vec.values.add(i) ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }).collect()
        }
    } unsafe fn ffi_to(obj : ArrayOfArraysOfHashes) -> * mut
    ArrayOfArraysOfHashesFFI
    {
        rs_ffi_interfaces ::
        boxed(ArrayOfArraysOfHashesFFI(rs_ffi_interfaces ::
        boxed({
            let vec = obj ; rs_ffi_interfaces :: VecFFI
            {
                count : vec.len(), values : rs_ffi_interfaces ::
                boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                boxed({
                    let vec = o ; rs_ffi_interfaces :: VecFFI
                    {
                        count : vec.len(), values : rs_ffi_interfaces ::
                        boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                        FFIConversion :: ffi_to(o)).collect())
                    }
                })).collect())
            }
        })))
    } unsafe fn destroy(ffi : * mut ArrayOfArraysOfHashesFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for ArrayOfArraysOfHashesFFI
{
    fn drop(& mut self)
    { unsafe { rs_ffi_interfaces :: unbox_any(self.0) ; } }
}
pub struct BinaryData(pub Vec < u8 >) ; #[repr(C)] #[derive(Clone, Debug)] pub
struct BinaryDataFFI(* mut rs_ffi_interfaces :: VecFFI < u8 >,) ; impl
rs_ffi_interfaces :: FFIConversion < BinaryData > for BinaryDataFFI
{
    unsafe fn ffi_from(ffi : * mut BinaryDataFFI) -> BinaryData
    {
        let ffi_ref = & * ffi ;
        BinaryData({
            let vec = & * ffi_ref.0 ; std :: slice ::
            from_raw_parts(vec.values as * const u8, vec.count).to_vec()
        },)
    } unsafe fn ffi_to(obj : BinaryData) -> * mut BinaryDataFFI
    {
        rs_ffi_interfaces ::
        boxed(BinaryDataFFI(rs_ffi_interfaces ::
        boxed({
            let vec = obj.0 ; rs_ffi_interfaces :: VecFFI
            {
                count : vec.len(), values : rs_ffi_interfaces ::
                boxed_vec(vec.clone())
            }
        }),))
    } unsafe fn destroy(ffi : * mut BinaryDataFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for BinaryDataFFI
{
    fn drop(& mut self)
    {
        unsafe
        { let ffi_ref = self ; rs_ffi_interfaces :: unbox_any(ffi_ref.0) ; ; }
    }
}
pub struct IdentifierBytes32(pub [u8 ; 32]) ; #[repr(C)]
#[derive(Clone, Debug)] pub struct IdentifierBytes32FFI(* mut [u8 ; 32],) ;
impl rs_ffi_interfaces :: FFIConversion < IdentifierBytes32 > for
IdentifierBytes32FFI
{
    unsafe fn ffi_from(ffi : * mut IdentifierBytes32FFI) -> IdentifierBytes32
    { let ffi_ref = & * ffi ; IdentifierBytes32(* ffi_ref.0,) } unsafe fn
    ffi_to(obj : IdentifierBytes32) -> * mut IdentifierBytes32FFI
    {
        rs_ffi_interfaces ::
        boxed(IdentifierBytes32FFI(rs_ffi_interfaces :: boxed(obj.0),))
    } unsafe fn destroy(ffi : * mut IdentifierBytes32FFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for IdentifierBytes32FFI
{
    fn drop(& mut self)
    {
        unsafe
        { let ffi_ref = self ; rs_ffi_interfaces :: unbox_any(ffi_ref.0) ; }
    }
}
pub struct Identifier(pub IdentifierBytes32) ; #[repr(C)]
#[derive(Clone, Debug)] pub struct IdentifierFFI(* mut IdentifierBytes32FFI,)
; impl rs_ffi_interfaces :: FFIConversion < Identifier > for IdentifierFFI
{
    unsafe fn ffi_from(ffi : * mut IdentifierFFI) -> Identifier
    {
        let ffi_ref = & * ffi ;
        Identifier(rs_ffi_interfaces :: FFIConversion :: ffi_from(ffi_ref.0),)
    } unsafe fn ffi_to(obj : Identifier) -> * mut IdentifierFFI
    {
        rs_ffi_interfaces ::
        boxed(IdentifierFFI(rs_ffi_interfaces :: FFIConversion ::
        ffi_to(obj.0),))
    } unsafe fn destroy(ffi : * mut IdentifierFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for IdentifierFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < IdentifierBytes32FFI as rs_ffi_interfaces
            :: FFIConversion < IdentifierBytes32 >> :: destroy(ffi_ref.0) ;
        }
    }
}
pub struct DataContractNotPresentError { data_contract_id : Identifier, }
#[doc = "FFI-representation of the"] #[doc = "DataContractNotPresentError"]
#[repr(C)] #[derive(Clone, Debug)] pub struct DataContractNotPresentErrorFFI
{ pub data_contract_id : * mut IdentifierFFI, } impl rs_ffi_interfaces ::
FFIConversion < DataContractNotPresentError > for
DataContractNotPresentErrorFFI
{
    unsafe fn ffi_from(ffi : * mut DataContractNotPresentErrorFFI) ->
    DataContractNotPresentError
    {
        let ffi_ref = & * ffi ; DataContractNotPresentError
        {
            data_contract_id : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.data_contract_id),
        }
    } unsafe fn ffi_to(obj : DataContractNotPresentError) -> * mut
    DataContractNotPresentErrorFFI
    {
        rs_ffi_interfaces ::
        boxed(DataContractNotPresentErrorFFI
        {
            data_contract_id : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.data_contract_id),
        })
    } unsafe fn destroy(ffi : * mut DataContractNotPresentErrorFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for DataContractNotPresentErrorFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < IdentifierFFI as rs_ffi_interfaces ::
            FFIConversion < Identifier >> :: destroy(ffi_ref.data_contract_id)
            ;
        }
    }
}
pub enum ProtocolError
{
    IdentifierError(String), StringDecodeError(String),
    StringDecodeError2(String, u32), EmptyPublicKeyDataError,
    MaxEncodedBytesReachedError
    { max_size_kbytes : usize, size_hit : usize, }, EncodingError(String),
    EncodingError2(& 'static str),
    DataContractNotPresentError(DataContractNotPresentError),
} #[doc = "FFI-representation of the"] #[doc = "ProtocolError"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
ProtocolErrorFFI
{
    IdentifierError(* mut std :: os :: raw :: c_char),
    StringDecodeError(* mut std :: os :: raw :: c_char),
    StringDecodeError2(* mut std :: os :: raw :: c_char, u32),
    EmptyPublicKeyDataError, MaxEncodedBytesReachedError
    { max_size_kbytes : usize, size_hit : usize },
    EncodingError(* mut std :: os :: raw :: c_char),
    EncodingError2(* mut std :: os :: raw :: c_char),
    DataContractNotPresentError(* mut DataContractNotPresentErrorFFI),
} impl rs_ffi_interfaces :: FFIConversion < ProtocolError > for
ProtocolErrorFFI
{
    unsafe fn ffi_from(ffi : * mut ProtocolErrorFFI) -> ProtocolError
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            ProtocolErrorFFI :: IdentifierError(o_0,) => ProtocolError ::
            IdentifierError(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0),), ProtocolErrorFFI :: StringDecodeError(o_0,) =>
            ProtocolError ::
            StringDecodeError(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0),), ProtocolErrorFFI ::
            StringDecodeError2(o_0, o_1,) => ProtocolError ::
            StringDecodeError2(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0), * o_1,), ProtocolErrorFFI ::
            EmptyPublicKeyDataError => ProtocolError ::
            EmptyPublicKeyDataError, ProtocolErrorFFI ::
            MaxEncodedBytesReachedError { max_size_kbytes, size_hit, } =>
            ProtocolError :: MaxEncodedBytesReachedError
            { max_size_kbytes : * max_size_kbytes, size_hit : * size_hit, },
            ProtocolErrorFFI :: EncodingError(o_0,) => ProtocolError ::
            EncodingError(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0),), ProtocolErrorFFI :: EncodingError2(o_0,) =>
            ProtocolError ::
            EncodingError2(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0),), ProtocolErrorFFI ::
            DataContractNotPresentError(o_0,) => ProtocolError ::
            DataContractNotPresentError(rs_ffi_interfaces :: FFIConversion ::
            ffi_from(* o_0),)
        }
    } unsafe fn ffi_to(obj : ProtocolError) -> * mut ProtocolErrorFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            ProtocolError :: IdentifierError(o_0,) => ProtocolErrorFFI ::
            IdentifierError(rs_ffi_interfaces :: FFIConversion ::
            ffi_to(o_0),), ProtocolError :: StringDecodeError(o_0,) =>
            ProtocolErrorFFI ::
            StringDecodeError(rs_ffi_interfaces :: FFIConversion ::
            ffi_to(o_0),), ProtocolError :: StringDecodeError2(o_0, o_1,) =>
            ProtocolErrorFFI ::
            StringDecodeError2(rs_ffi_interfaces :: FFIConversion ::
            ffi_to(o_0), o_1,), ProtocolError :: EmptyPublicKeyDataError =>
            ProtocolErrorFFI :: EmptyPublicKeyDataError, ProtocolError ::
            MaxEncodedBytesReachedError { max_size_kbytes, size_hit, } =>
            ProtocolErrorFFI :: MaxEncodedBytesReachedError
            { max_size_kbytes : max_size_kbytes, size_hit : size_hit, },
            ProtocolError :: EncodingError(o_0,) => ProtocolErrorFFI ::
            EncodingError(rs_ffi_interfaces :: FFIConversion :: ffi_to(o_0),),
            ProtocolError :: EncodingError2(o_0,) => ProtocolErrorFFI ::
            EncodingError2(rs_ffi_interfaces :: FFIConversion ::
            ffi_to(o_0),), ProtocolError :: DataContractNotPresentError(o_0,)
            => ProtocolErrorFFI ::
            DataContractNotPresentError(rs_ffi_interfaces :: FFIConversion ::
            ffi_to(o_0),)
        })
    } unsafe fn destroy(ffi : * mut ProtocolErrorFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for ProtocolErrorFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                ProtocolErrorFFI :: IdentifierError(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                ProtocolErrorFFI :: StringDecodeError(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                ProtocolErrorFFI :: StringDecodeError2(o_0, o_1,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                ProtocolErrorFFI :: EmptyPublicKeyDataError => {},
                ProtocolErrorFFI :: MaxEncodedBytesReachedError
                { max_size_kbytes, size_hit, } => { {} {} }, ProtocolErrorFFI
                :: EncodingError(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
                ProtocolErrorFFI :: EncodingError2(o_0,) =>
                {
                    < std :: os :: raw :: c_char as rs_ffi_interfaces ::
                    FFIConversion < & str >> :: destroy(o_0.to_owned())
                }, ProtocolErrorFFI :: DataContractNotPresentError(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
            }
        }
    }
}
pub struct TestStruct
{
    pub map_key_simple_value_simple : BTreeMap < u32, u32 >, pub
    map_key_simple_value_complex : BTreeMap < u32, UInt256 >, pub
    map_key_simple_value_vec_simple : BTreeMap < u32, Vec < u32 > >, pub
    map_key_simple_value_vec_complex : BTreeMap < u32, Vec < UInt256 > >, pub
    map_key_simple_value_map_key_simple_value_simple : BTreeMap < u32,
    BTreeMap < u32, u32 > >, pub
    map_key_simple_value_map_key_simple_value_complex : BTreeMap < u32,
    BTreeMap < u32, UInt256 > >, pub
    map_key_simple_value_map_key_simple_value_vec_simple : BTreeMap < u32,
    BTreeMap < u32, Vec < u32 > > >, pub
    map_key_simple_value_map_key_simple_value_vec_complex : BTreeMap < u32,
    BTreeMap < u32, Vec < UInt256 > > >, pub map_key_complex_value_simple :
    BTreeMap < UInt256, u32 >, pub map_key_complex_value_complex : BTreeMap <
    UInt256, UInt256 >, pub map_key_complex_value_vec_simple : BTreeMap <
    UInt256, Vec < u32 > >, pub map_key_complex_value_vec_complex : BTreeMap <
    UInt256, Vec < UInt256 > >, pub
    map_key_complex_value_map_key_simple_value_vec_simple : BTreeMap <
    UInt256, BTreeMap < u32, Vec < u32 > > >, pub
    map_key_complex_value_map_key_simple_value_vec_complex : BTreeMap <
    UInt256, BTreeMap < u32, Vec < UInt256 > > >,
} #[doc = "FFI-representation of the"] #[doc = "TestStruct"] #[repr(C)]
#[derive(Clone, Debug)] pub struct TestStructFFI
{
    pub map_key_simple_value_simple : * mut rs_ffi_interfaces :: MapFFI < u32,
    u32 >, pub map_key_simple_value_complex : * mut rs_ffi_interfaces ::
    MapFFI < u32, * mut [u8 ; 32] >, pub map_key_simple_value_vec_simple : *
    mut rs_ffi_interfaces :: MapFFI < u32, * mut rs_ffi_interfaces :: VecFFI <
    u32 > >, pub map_key_simple_value_vec_complex : * mut rs_ffi_interfaces ::
    MapFFI < u32, * mut rs_ffi_interfaces :: VecFFI < * mut [u8 ; 32] > >, pub
    map_key_simple_value_map_key_simple_value_simple : * mut rs_ffi_interfaces
    :: MapFFI < u32, * mut rs_ffi_interfaces :: MapFFI < u32, u32 > >, pub
    map_key_simple_value_map_key_simple_value_complex : * mut
    rs_ffi_interfaces :: MapFFI < u32, * mut rs_ffi_interfaces :: MapFFI <
    u32, * mut [u8 ; 32] > >, pub
    map_key_simple_value_map_key_simple_value_vec_simple : * mut
    rs_ffi_interfaces :: MapFFI < u32, * mut rs_ffi_interfaces :: MapFFI <
    u32, * mut rs_ffi_interfaces :: VecFFI < u32 > > >, pub
    map_key_simple_value_map_key_simple_value_vec_complex : * mut
    rs_ffi_interfaces :: MapFFI < u32, * mut rs_ffi_interfaces :: MapFFI <
    u32, * mut rs_ffi_interfaces :: VecFFI < * mut [u8 ; 32] > > >, pub
    map_key_complex_value_simple : * mut rs_ffi_interfaces :: MapFFI < * mut
    [u8 ; 32], u32 >, pub map_key_complex_value_complex : * mut
    rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut [u8 ; 32] >, pub
    map_key_complex_value_vec_simple : * mut rs_ffi_interfaces :: MapFFI < *
    mut [u8 ; 32], * mut rs_ffi_interfaces :: VecFFI < u32 > >, pub
    map_key_complex_value_vec_complex : * mut rs_ffi_interfaces :: MapFFI < *
    mut [u8 ; 32], * mut rs_ffi_interfaces :: VecFFI < * mut [u8 ; 32] > >,
    pub map_key_complex_value_map_key_simple_value_vec_simple : * mut
    rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut rs_ffi_interfaces ::
    MapFFI < u32, * mut rs_ffi_interfaces :: VecFFI < u32 > > >, pub
    map_key_complex_value_map_key_simple_value_vec_complex : * mut
    rs_ffi_interfaces :: MapFFI < * mut [u8 ; 32], * mut rs_ffi_interfaces ::
    MapFFI < u32, * mut rs_ffi_interfaces :: VecFFI < * mut [u8 ; 32] > > >,
} impl rs_ffi_interfaces :: FFIConversion < TestStruct > for TestStructFFI
{
    unsafe fn ffi_from(ffi : * mut TestStructFFI) -> TestStruct
    {
        let ffi_ref = & * ffi ; TestStruct
        {
            map_key_simple_value_simple :
            {
                let map = & * ffi_ref.map_key_simple_value_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value = *
                    map.values.add(i) ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_complex :
            {
                let map = & * ffi_ref.map_key_simple_value_complex ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_vec_simple :
            {
                let map = & * ffi_ref.map_key_simple_value_vec_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let vec = & * * map.values.add(i) ; std :: slice ::
                        from_raw_parts(vec.values as * const u32,
                        vec.count).to_vec()
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_vec_complex :
            {
                let map = & * ffi_ref.map_key_simple_value_vec_complex ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let vec = & * * map.values.add(i) ;
                        (0 ..
                        vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                        ffi_from(* vec.values.add(i))).collect()
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_map_key_simple_value_simple :
            {
                let map = & *
                ffi_ref.map_key_simple_value_map_key_simple_value_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value = *
                            map.values.add(i) ; acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_map_key_simple_value_complex :
            {
                let map = & *
                ffi_ref.map_key_simple_value_map_key_simple_value_complex ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value = rs_ffi_interfaces
                            :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                            acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_map_key_simple_value_vec_simple :
            {
                let map = & *
                ffi_ref.map_key_simple_value_map_key_simple_value_vec_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value =
                            {
                                let vec = & * * map.values.add(i) ; std :: slice ::
                                from_raw_parts(vec.values as * const u32,
                                vec.count).to_vec()
                            } ; acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_simple_value_map_key_simple_value_vec_complex :
            {
                let map = & *
                ffi_ref.map_key_simple_value_map_key_simple_value_vec_complex
                ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = * map.keys.add(i) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value =
                            {
                                let vec = & * * map.values.add(i) ;
                                (0 ..
                                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                                ffi_from(* vec.values.add(i))).collect()
                            } ; acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_simple :
            {
                let map = & * ffi_ref.map_key_complex_value_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = *
                    map.values.add(i) ; acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_complex :
            {
                let map = & * ffi_ref.map_key_complex_value_complex ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_vec_simple :
            {
                let map = & * ffi_ref.map_key_complex_value_vec_simple ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let vec = & * * map.values.add(i) ; std :: slice ::
                        from_raw_parts(vec.values as * const u32,
                        vec.count).to_vec()
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_vec_complex :
            {
                let map = & * ffi_ref.map_key_complex_value_vec_complex ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let vec = & * * map.values.add(i) ;
                        (0 ..
                        vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                        ffi_from(* vec.values.add(i))).collect()
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_map_key_simple_value_vec_simple :
            {
                let map = & *
                ffi_ref.map_key_complex_value_map_key_simple_value_vec_simple
                ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value =
                            {
                                let vec = & * * map.values.add(i) ; std :: slice ::
                                from_raw_parts(vec.values as * const u32,
                                vec.count).to_vec()
                            } ; acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            }, map_key_complex_value_map_key_simple_value_vec_complex :
            {
                let map = & *
                ffi_ref.map_key_complex_value_map_key_simple_value_vec_complex
                ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = * map.keys.add(i) ; let value =
                            {
                                let vec = & * * map.values.add(i) ;
                                (0 ..
                                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                                ffi_from(* vec.values.add(i))).collect()
                            } ; acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            },
        }
    } unsafe fn ffi_to(obj : TestStruct) -> * mut TestStructFFI
    {
        rs_ffi_interfaces ::
        boxed(TestStructFFI
        {
            map_key_simple_value_simple : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_simple_value_simple ; rs_ffi_interfaces
                :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | o).collect())
                }
            }), map_key_simple_value_complex : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_simple_value_complex ; rs_ffi_interfaces
                :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), map_key_simple_value_vec_simple : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_simple_value_vec_simple ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let vec = o ; rs_ffi_interfaces :: VecFFI
                        {
                            count : vec.len(), values : rs_ffi_interfaces ::
                            boxed_vec(vec.clone())
                        }
                    })).collect())
                }
            }), map_key_simple_value_vec_complex : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_simple_value_vec_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let vec = o ; rs_ffi_interfaces :: VecFFI
                        {
                            count : vec.len(), values : rs_ffi_interfaces ::
                            boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                            FFIConversion :: ffi_to(o)).collect())
                        }
                    })).collect())
                }
            }), map_key_simple_value_map_key_simple_value_simple :
            rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_simple_value_map_key_simple_value_simple
                ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | o).collect())
                        }
                    })).collect())
                }
            }), map_key_simple_value_map_key_simple_value_complex :
            rs_ffi_interfaces ::
            boxed({
                let map =
                obj.map_key_simple_value_map_key_simple_value_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            :: FFIConversion :: ffi_to(o)).collect())
                        }
                    })).collect())
                }
            }), map_key_simple_value_map_key_simple_value_vec_simple :
            rs_ffi_interfaces ::
            boxed({
                let map =
                obj.map_key_simple_value_map_key_simple_value_vec_simple ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            ::
                            boxed({
                                let vec = o ; rs_ffi_interfaces :: VecFFI
                                {
                                    count : vec.len(), values : rs_ffi_interfaces ::
                                    boxed_vec(vec.clone())
                                }
                            })).collect())
                        }
                    })).collect())
                }
            }), map_key_simple_value_map_key_simple_value_vec_complex :
            rs_ffi_interfaces ::
            boxed({
                let map =
                obj.map_key_simple_value_map_key_simple_value_vec_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | o).collect()),
                    values : rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            ::
                            boxed({
                                let vec = o ; rs_ffi_interfaces :: VecFFI
                                {
                                    count : vec.len(), values : rs_ffi_interfaces ::
                                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                                    FFIConversion :: ffi_to(o)).collect())
                                }
                            })).collect())
                        }
                    })).collect())
                }
            }), map_key_complex_value_simple : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_complex_value_simple ; rs_ffi_interfaces
                :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | o).collect())
                }
            }), map_key_complex_value_complex : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_complex_value_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), map_key_complex_value_vec_simple : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_complex_value_vec_simple ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let vec = o ; rs_ffi_interfaces :: VecFFI
                        {
                            count : vec.len(), values : rs_ffi_interfaces ::
                            boxed_vec(vec.clone())
                        }
                    })).collect())
                }
            }), map_key_complex_value_vec_complex : rs_ffi_interfaces ::
            boxed({
                let map = obj.map_key_complex_value_vec_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let vec = o ; rs_ffi_interfaces :: VecFFI
                        {
                            count : vec.len(), values : rs_ffi_interfaces ::
                            boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                            FFIConversion :: ffi_to(o)).collect())
                        }
                    })).collect())
                }
            }), map_key_complex_value_map_key_simple_value_vec_simple :
            rs_ffi_interfaces ::
            boxed({
                let map =
                obj.map_key_complex_value_map_key_simple_value_vec_simple ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            ::
                            boxed({
                                let vec = o ; rs_ffi_interfaces :: VecFFI
                                {
                                    count : vec.len(), values : rs_ffi_interfaces ::
                                    boxed_vec(vec.clone())
                                }
                            })).collect())
                        }
                    })).collect())
                }
            }), map_key_complex_value_map_key_simple_value_vec_complex :
            rs_ffi_interfaces ::
            boxed({
                let map =
                obj.map_key_complex_value_map_key_simple_value_vec_complex ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | o).collect()),
                            values : rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            ::
                            boxed({
                                let vec = o ; rs_ffi_interfaces :: VecFFI
                                {
                                    count : vec.len(), values : rs_ffi_interfaces ::
                                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                                    FFIConversion :: ffi_to(o)).collect())
                                }
                            })).collect())
                        }
                    })).collect())
                }
            }),
        })
    } unsafe fn destroy(ffi : * mut TestStructFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TestStructFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_simple) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_complex) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_vec_simple) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_vec_complex) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_map_key_simple_value_simple)
            ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_map_key_simple_value_complex)
            ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_map_key_simple_value_vec_simple)
            ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_simple_value_map_key_simple_value_vec_complex)
            ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_simple) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_complex) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_vec_simple) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_vec_complex) ; ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_map_key_simple_value_vec_simple)
            ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.map_key_complex_value_map_key_simple_value_vec_complex)
            ; ;
        }
    }
}
#[warn(non_camel_case_types)] #[repr(C)] pub enum ProcessingError
{
    None = 0, PersistInRetrieval = 1, LocallyStored = 2, ParseError = 3,
    HasNoBaseBlockHash = 4, UnknownBlockHash = 5,
} #[doc = "FFI-representation of the"] #[doc = "ProcessingError"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
ProcessingErrorFFI
{
    None = 0, PersistInRetrieval = 1, LocallyStored = 2, ParseError = 3,
    HasNoBaseBlockHash = 4, UnknownBlockHash = 5,
} impl rs_ffi_interfaces :: FFIConversion < ProcessingError > for
ProcessingErrorFFI
{
    unsafe fn ffi_from(ffi : * mut ProcessingErrorFFI) -> ProcessingError
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            ProcessingErrorFFI :: None => ProcessingError :: None,
            ProcessingErrorFFI :: PersistInRetrieval => ProcessingError ::
            PersistInRetrieval, ProcessingErrorFFI :: LocallyStored =>
            ProcessingError :: LocallyStored, ProcessingErrorFFI :: ParseError
            => ProcessingError :: ParseError, ProcessingErrorFFI ::
            HasNoBaseBlockHash => ProcessingError :: HasNoBaseBlockHash,
            ProcessingErrorFFI :: UnknownBlockHash => ProcessingError ::
            UnknownBlockHash
        }
    } unsafe fn ffi_to(obj : ProcessingError) -> * mut ProcessingErrorFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            ProcessingError :: None => ProcessingErrorFFI :: None,
            ProcessingError :: PersistInRetrieval => ProcessingErrorFFI ::
            PersistInRetrieval, ProcessingError :: LocallyStored =>
            ProcessingErrorFFI :: LocallyStored, ProcessingError :: ParseError
            => ProcessingErrorFFI :: ParseError, ProcessingError ::
            HasNoBaseBlockHash => ProcessingErrorFFI :: HasNoBaseBlockHash,
            ProcessingError :: UnknownBlockHash => ProcessingErrorFFI ::
            UnknownBlockHash
        })
    } unsafe fn destroy(ffi : * mut ProcessingErrorFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for ProcessingErrorFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                ProcessingErrorFFI :: None => {}, ProcessingErrorFFI ::
                PersistInRetrieval => {}, ProcessingErrorFFI :: LocallyStored
                => {}, ProcessingErrorFFI :: ParseError => {},
                ProcessingErrorFFI :: HasNoBaseBlockHash => {},
                ProcessingErrorFFI :: UnknownBlockHash => {},
            }
        }
    }
}
pub struct QRInfoResult
{
    pub error_status : crate :: processing :: processing_error ::
    ProcessingError, pub result_at_tip : crate :: processing ::
    mn_listdiff_result :: MNListDiffResult, pub result_at_h : crate ::
    processing :: mn_listdiff_result :: MNListDiffResult, pub result_at_h_c :
    crate :: processing :: mn_listdiff_result :: MNListDiffResult, pub
    result_at_h_2c : crate :: processing :: mn_listdiff_result ::
    MNListDiffResult, pub result_at_h_3c : crate :: processing ::
    mn_listdiff_result :: MNListDiffResult, pub result_at_h_4c : Option <
    crate :: processing :: mn_listdiff_result :: MNListDiffResult >, pub
    snapshot_at_h_c : crate :: models :: snapshot :: LLMQSnapshot, pub
    snapshot_at_h_2c : crate :: models :: snapshot :: LLMQSnapshot, pub
    snapshot_at_h_3c : crate :: models :: snapshot :: LLMQSnapshot, pub
    snapshot_at_h_4c : Option < crate :: models :: snapshot :: LLMQSnapshot >,
    pub extra_share : bool, pub last_quorum_per_index : Vec < crate :: models
    :: llmq_entry :: LLMQEntry >, pub quorum_snapshot_list : Vec < crate ::
    models :: snapshot :: LLMQSnapshot >, pub mn_list_diff_list : Vec < crate
    :: processing :: mn_listdiff_result :: MNListDiffResult >,
} #[doc = "FFI-representation of the"] #[doc = "QRInfoResult"] #[repr(C)]
#[derive(Clone, Debug)] pub struct QRInfoResultFFI
{
    pub error_status : * mut crate :: processing :: processing_error ::
    ProcessingErrorFFI, pub result_at_tip : * mut crate :: processing ::
    mn_listdiff_result :: MNListDiffResultFFI, pub result_at_h : * mut crate
    :: processing :: mn_listdiff_result :: MNListDiffResultFFI, pub
    result_at_h_c : * mut crate :: processing :: mn_listdiff_result ::
    MNListDiffResultFFI, pub result_at_h_2c : * mut crate :: processing ::
    mn_listdiff_result :: MNListDiffResultFFI, pub result_at_h_3c : * mut
    crate :: processing :: mn_listdiff_result :: MNListDiffResultFFI, pub
    result_at_h_4c : * mut crate :: processing :: mn_listdiff_result ::
    MNListDiffResultFFI, pub snapshot_at_h_c : * mut crate :: models ::
    snapshot :: LLMQSnapshotFFI, pub snapshot_at_h_2c : * mut crate :: models
    :: snapshot :: LLMQSnapshotFFI, pub snapshot_at_h_3c : * mut crate ::
    models :: snapshot :: LLMQSnapshotFFI, pub snapshot_at_h_4c : * mut crate
    :: models :: snapshot :: LLMQSnapshotFFI, pub extra_share : bool, pub
    last_quorum_per_index : * mut rs_ffi_interfaces :: VecFFI < * mut crate ::
    models :: llmq_entry :: LLMQEntryFFI >, pub quorum_snapshot_list : * mut
    rs_ffi_interfaces :: VecFFI < * mut crate :: models :: snapshot ::
    LLMQSnapshotFFI >, pub mn_list_diff_list : * mut rs_ffi_interfaces ::
    VecFFI < * mut crate :: processing :: mn_listdiff_result ::
    MNListDiffResultFFI >,
} impl rs_ffi_interfaces :: FFIConversion < QRInfoResult > for QRInfoResultFFI
{
    unsafe fn ffi_from(ffi : * mut QRInfoResultFFI) -> QRInfoResult
    {
        let ffi_ref = & * ffi ; QRInfoResult
        {
            error_status : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.error_status), result_at_tip : rs_ffi_interfaces
            :: FFIConversion :: ffi_from(ffi_ref.result_at_tip), result_at_h :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.result_at_h), result_at_h_c : rs_ffi_interfaces
            :: FFIConversion :: ffi_from(ffi_ref.result_at_h_c),
            result_at_h_2c : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.result_at_h_2c), result_at_h_3c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.result_at_h_3c), result_at_h_4c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.result_at_h_4c), snapshot_at_h_c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.snapshot_at_h_c), snapshot_at_h_2c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.snapshot_at_h_2c), snapshot_at_h_3c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.snapshot_at_h_3c), snapshot_at_h_4c :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.snapshot_at_h_4c), extra_share :
            ffi_ref.extra_share, last_quorum_per_index :
            {
                let vec = & * ffi_ref.last_quorum_per_index ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }, quorum_snapshot_list :
            {
                let vec = & * ffi_ref.quorum_snapshot_list ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }, mn_list_diff_list :
            {
                let vec = & * ffi_ref.mn_list_diff_list ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            },
        }
    } unsafe fn ffi_to(obj : QRInfoResult) -> * mut QRInfoResultFFI
    {
        rs_ffi_interfaces ::
        boxed(QRInfoResultFFI
        {
            error_status : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.error_status), result_at_tip : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.result_at_tip), result_at_h :
            rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.result_at_h),
            result_at_h_c : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.result_at_h_c), result_at_h_2c : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.result_at_h_2c), result_at_h_3c :
            rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.result_at_h_3c),
            result_at_h_4c : rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.result_at_h_4c), snapshot_at_h_c :
            rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.snapshot_at_h_c),
            snapshot_at_h_2c : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.snapshot_at_h_2c), snapshot_at_h_3c : rs_ffi_interfaces
            :: FFIConversion :: ffi_to(obj.snapshot_at_h_3c), snapshot_at_h_4c
            : rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.snapshot_at_h_4c), extra_share : obj.extra_share,
            last_quorum_per_index : rs_ffi_interfaces ::
            boxed({
                let vec = obj.last_quorum_per_index ; rs_ffi_interfaces ::
                VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }), quorum_snapshot_list : rs_ffi_interfaces ::
            boxed({
                let vec = obj.quorum_snapshot_list ; rs_ffi_interfaces ::
                VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }), mn_list_diff_list : rs_ffi_interfaces ::
            boxed({
                let vec = obj.mn_list_diff_list ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }),
        })
    } unsafe fn destroy(ffi : * mut QRInfoResultFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for QRInfoResultFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < crate :: processing :: processing_error ::
            ProcessingErrorFFI as rs_ffi_interfaces :: FFIConversion < crate
            :: processing :: processing_error :: ProcessingError >> ::
            destroy(ffi_ref.error_status) ; < crate :: processing ::
            mn_listdiff_result :: MNListDiffResultFFI as rs_ffi_interfaces ::
            FFIConversion < crate :: processing :: mn_listdiff_result ::
            MNListDiffResult >> :: destroy(ffi_ref.result_at_tip) ; < crate ::
            processing :: mn_listdiff_result :: MNListDiffResultFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: processing ::
            mn_listdiff_result :: MNListDiffResult >> ::
            destroy(ffi_ref.result_at_h) ; < crate :: processing ::
            mn_listdiff_result :: MNListDiffResultFFI as rs_ffi_interfaces ::
            FFIConversion < crate :: processing :: mn_listdiff_result ::
            MNListDiffResult >> :: destroy(ffi_ref.result_at_h_c) ; < crate ::
            processing :: mn_listdiff_result :: MNListDiffResultFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: processing ::
            mn_listdiff_result :: MNListDiffResult >> ::
            destroy(ffi_ref.result_at_h_2c) ; < crate :: processing ::
            mn_listdiff_result :: MNListDiffResultFFI as rs_ffi_interfaces ::
            FFIConversion < crate :: processing :: mn_listdiff_result ::
            MNListDiffResult >> :: destroy(ffi_ref.result_at_h_3c) ; if!
            ffi_ref.result_at_h_4c.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.result_at_h_4c) ; } ; <
            crate :: models :: snapshot :: LLMQSnapshotFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: models :: snapshot
            :: LLMQSnapshot >> :: destroy(ffi_ref.snapshot_at_h_c) ; < crate
            :: models :: snapshot :: LLMQSnapshotFFI as rs_ffi_interfaces ::
            FFIConversion < crate :: models :: snapshot :: LLMQSnapshot >> ::
            destroy(ffi_ref.snapshot_at_h_2c) ; < crate :: models :: snapshot
            :: LLMQSnapshotFFI as rs_ffi_interfaces :: FFIConversion < crate
            :: models :: snapshot :: LLMQSnapshot >> ::
            destroy(ffi_ref.snapshot_at_h_3c) ; if!
            ffi_ref.snapshot_at_h_4c.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.snapshot_at_h_4c) ; } ;
            {} ; rs_ffi_interfaces :: unbox_any(ffi_ref.last_quorum_per_index)
            ; ; rs_ffi_interfaces :: unbox_any(ffi_ref.quorum_snapshot_list) ;
            ; rs_ffi_interfaces :: unbox_any(ffi_ref.mn_list_diff_list) ; ;
        }
    }
}
pub fn
address_from_hash160(hash : UInt160, chain_type : crate :: chain :: common ::
chain_type :: ChainType,) -> String
{
    let script_map = chain_type.script_map() ; address ::
    from_hash160_for_script_map(& hash, & script_map)
} #[doc = "FFI-representation of the"] #[doc = "address_from_hash160"]
#[doc = r" # Safety"] #[no_mangle] pub unsafe extern "C" fn
ffi_address_from_hash160(hash : * mut [u8 ; 20], chain_type : * mut crate ::
chain :: common :: chain_type :: ChainTypeFFI) -> * mut std :: os :: raw ::
c_char
{
    let obj =
    address_from_hash160(rs_ffi_interfaces :: FFIConversion :: ffi_from(hash),
    rs_ffi_interfaces :: FFIConversion :: ffi_from(chain_type)) ;
    rs_ffi_interfaces :: FFIConversion :: ffi_to(obj)
}
pub fn
address_with_script_pubkey(script : Vec < u8 >, chain_type : crate :: chain ::
common :: chain_type :: ChainType,) -> Option < String >
{ address :: with_script_pub_key(& script, & chain_type.script_map()) }
#[doc = "FFI-representation of the"] #[doc = "address_with_script_pubkey"]
#[doc = r" # Safety"] #[no_mangle] pub unsafe extern "C" fn
ffi_address_with_script_pubkey(script : * mut rs_ffi_interfaces :: VecFFI < u8
>, chain_type : * mut crate :: chain :: common :: chain_type :: ChainTypeFFI)
-> * mut std :: os :: raw :: c_char
{
    let obj =
    address_with_script_pubkey({
        let vec = & * script ; std :: slice ::
        from_raw_parts(vec.values as * const u8, vec.count).to_vec()
    }, rs_ffi_interfaces :: FFIConversion :: ffi_from(chain_type)) ;
    rs_ffi_interfaces :: FFIConversion :: ffi_to_opt(obj)
}
pub fn
address_with_script_sig(script : Vec < u8 >, chain_type : crate :: chain ::
common :: chain_type :: ChainType,) -> Option < String >
{ address :: with_script_sig(& script, & chain_type.script_map(),) }
#[doc = "FFI-representation of the"] #[doc = "address_with_script_sig"]
#[doc = r" # Safety"] #[no_mangle] pub unsafe extern "C" fn
ffi_address_with_script_sig(script : * mut rs_ffi_interfaces :: VecFFI < u8 >,
chain_type : * mut crate :: chain :: common :: chain_type :: ChainTypeFFI) ->
* mut std :: os :: raw :: c_char
{
    let obj =
    address_with_script_sig({
        let vec = & * script ; std :: slice ::
        from_raw_parts(vec.values as * const u8, vec.count).to_vec()
    }, rs_ffi_interfaces :: FFIConversion :: ffi_from(chain_type)) ;
    rs_ffi_interfaces :: FFIConversion :: ffi_to_opt(obj)
}
pub fn
script_pubkey_for_address(address : Option < String >, chain_type : crate ::
chain :: common :: chain_type :: ChainType,) -> Option < Vec < u8 > >
{
    address.map(| address |
    {
        Vec :: < u8 > ::
        script_pub_key_for_address(address.as_str(), &
        chain_type.script_map())
    })
} #[doc = "FFI-representation of the"] #[doc = "script_pubkey_for_address"]
#[doc = r" # Safety"] #[no_mangle] pub unsafe extern "C" fn
ffi_script_pubkey_for_address(address : * mut std :: os :: raw :: c_char,
chain_type : * mut crate :: chain :: common :: chain_type :: ChainTypeFFI) ->
* mut rs_ffi_interfaces :: VecFFI < u8 >
{
    let obj =
    script_pubkey_for_address(rs_ffi_interfaces :: FFIConversion ::
    ffi_from_opt(address), rs_ffi_interfaces :: FFIConversion ::
    ffi_from(chain_type)) ; match obj
    {
        Some(vec) => rs_ffi_interfaces ::
        boxed(rs_ffi_interfaces :: VecFFI :: new(vec.clone())), None => std ::
        ptr :: null_mut()
    }
}
pub fn
is_valid_dash_address_for_chain(address : Option < String >, chain_type :
crate :: chain :: common :: chain_type :: ChainType,) -> bool
{
    address.map_or(false, | address | address ::
    is_valid_dash_address_for_script_map(address.as_str(), &
    chain_type.script_map()))
} #[doc = "FFI-representation of the"]
#[doc = "is_valid_dash_address_for_chain"] #[doc = r" # Safety"] #[no_mangle]
pub unsafe extern "C" fn
ffi_is_valid_dash_address_for_chain(address : * mut std :: os :: raw ::
c_char, chain_type : * mut crate :: chain :: common :: chain_type ::
ChainTypeFFI) -> bool
{
    let obj =
    is_valid_dash_address_for_chain(rs_ffi_interfaces :: FFIConversion ::
    ffi_from_opt(address), rs_ffi_interfaces :: FFIConversion ::
    ffi_from(chain_type)) ; obj
}
#[repr(C)] pub enum ChainType
{ #[default] MainNet, TestNet, DevNet(DevnetType), }
#[doc = "FFI-representation of the"] #[doc = "ChainType"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
ChainTypeFFI { MainNet, TestNet, DevNet(* mut DevnetTypeFFI), } impl
rs_ffi_interfaces :: FFIConversion < ChainType > for ChainTypeFFI
{
    unsafe fn ffi_from(ffi : * mut ChainTypeFFI) -> ChainType
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            ChainTypeFFI :: MainNet => ChainType :: MainNet, ChainTypeFFI ::
            TestNet => ChainType :: TestNet, ChainTypeFFI :: DevNet(o_0,) =>
            ChainType ::
            DevNet(rs_ffi_interfaces :: FFIConversion :: ffi_from(* o_0),)
        }
    } unsafe fn ffi_to(obj : ChainType) -> * mut ChainTypeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            ChainType :: MainNet => ChainTypeFFI :: MainNet, ChainType ::
            TestNet => ChainTypeFFI :: TestNet, ChainType :: DevNet(o_0,) =>
            ChainTypeFFI ::
            DevNet(rs_ffi_interfaces :: FFIConversion :: ffi_to(o_0),)
        })
    } unsafe fn destroy(ffi : * mut ChainTypeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for ChainTypeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                ChainTypeFFI :: MainNet => {}, ChainTypeFFI :: TestNet => {},
                ChainTypeFFI :: DevNet(o_0,) =>
                { let o_0 = rs_ffi_interfaces :: unbox_any(o_0) ; },
            }
        }
    }
}
#[repr(C)] pub enum DevnetType
{
    JackDaniels = 0, Devnet333 = 1, Chacha = 2, #[default] Mojito = 3,
    WhiteRussian = 4, MiningTest = 5, Mobile2 = 6, Zero = 7, Screwdriver = 8,
    Absinthe = 9, Bintang = 10,
} #[doc = "FFI-representation of the"] #[doc = "DevnetType"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
DevnetTypeFFI
{
    JackDaniels = 0, Devnet333 = 1, Chacha = 2, Mojito = 3, WhiteRussian = 4,
    MiningTest = 5, Mobile2 = 6, Zero = 7, Screwdriver = 8, Absinthe = 9,
    Bintang = 10,
} impl rs_ffi_interfaces :: FFIConversion < DevnetType > for DevnetTypeFFI
{
    unsafe fn ffi_from(ffi : * mut DevnetTypeFFI) -> DevnetType
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            DevnetTypeFFI :: JackDaniels => DevnetType :: JackDaniels,
            DevnetTypeFFI :: Devnet333 => DevnetType :: Devnet333,
            DevnetTypeFFI :: Chacha => DevnetType :: Chacha, DevnetTypeFFI ::
            Mojito => DevnetType :: Mojito, DevnetTypeFFI :: WhiteRussian =>
            DevnetType :: WhiteRussian, DevnetTypeFFI :: MiningTest =>
            DevnetType :: MiningTest, DevnetTypeFFI :: Mobile2 => DevnetType
            :: Mobile2, DevnetTypeFFI :: Zero => DevnetType :: Zero,
            DevnetTypeFFI :: Screwdriver => DevnetType :: Screwdriver,
            DevnetTypeFFI :: Absinthe => DevnetType :: Absinthe, DevnetTypeFFI
            :: Bintang => DevnetType :: Bintang
        }
    } unsafe fn ffi_to(obj : DevnetType) -> * mut DevnetTypeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            DevnetType :: JackDaniels => DevnetTypeFFI :: JackDaniels,
            DevnetType :: Devnet333 => DevnetTypeFFI :: Devnet333, DevnetType
            :: Chacha => DevnetTypeFFI :: Chacha, DevnetType :: Mojito =>
            DevnetTypeFFI :: Mojito, DevnetType :: WhiteRussian =>
            DevnetTypeFFI :: WhiteRussian, DevnetType :: MiningTest =>
            DevnetTypeFFI :: MiningTest, DevnetType :: Mobile2 =>
            DevnetTypeFFI :: Mobile2, DevnetType :: Zero => DevnetTypeFFI ::
            Zero, DevnetType :: Screwdriver => DevnetTypeFFI :: Screwdriver,
            DevnetType :: Absinthe => DevnetTypeFFI :: Absinthe, DevnetType ::
            Bintang => DevnetTypeFFI :: Bintang
        })
    } unsafe fn destroy(ffi : * mut DevnetTypeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for DevnetTypeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                DevnetTypeFFI :: JackDaniels => {}, DevnetTypeFFI :: Devnet333
                => {}, DevnetTypeFFI :: Chacha => {}, DevnetTypeFFI :: Mojito
                => {}, DevnetTypeFFI :: WhiteRussian => {}, DevnetTypeFFI ::
                MiningTest => {}, DevnetTypeFFI :: Mobile2 => {},
                DevnetTypeFFI :: Zero => {}, DevnetTypeFFI :: Screwdriver =>
                {}, DevnetTypeFFI :: Absinthe => {}, DevnetTypeFFI :: Bintang
                => {},
            }
        }
    }
}
#[repr(C)] pub struct DKGParams
{
    pub interval : u32, pub phase_blocks : u32, pub mining_window_start : u32,
    pub mining_window_end : u32, pub bad_votes_threshold : u32,
} #[doc = "FFI-representation of the"] #[doc = "DKGParams"] #[repr(C)]
#[derive(Clone, Debug)] pub struct DKGParamsFFI
{
    pub interval : u32, pub phase_blocks : u32, pub mining_window_start : u32,
    pub mining_window_end : u32, pub bad_votes_threshold : u32,
} impl rs_ffi_interfaces :: FFIConversion < DKGParams > for DKGParamsFFI
{
    unsafe fn ffi_from(ffi : * mut DKGParamsFFI) -> DKGParams
    {
        let ffi_ref = & * ffi ; DKGParams
        {
            interval : ffi_ref.interval, phase_blocks : ffi_ref.phase_blocks,
            mining_window_start : ffi_ref.mining_window_start,
            mining_window_end : ffi_ref.mining_window_end, bad_votes_threshold
            : ffi_ref.bad_votes_threshold,
        }
    } unsafe fn ffi_to(obj : DKGParams) -> * mut DKGParamsFFI
    {
        rs_ffi_interfaces ::
        boxed(DKGParamsFFI
        {
            interval : obj.interval, phase_blocks : obj.phase_blocks,
            mining_window_start : obj.mining_window_start, mining_window_end :
            obj.mining_window_end, bad_votes_threshold :
            obj.bad_votes_threshold,
        })
    } unsafe fn destroy(ffi : * mut DKGParamsFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for DKGParamsFFI
{
    fn drop(& mut self)
    { unsafe { let ffi_ref = self ; {} ; {} ; {} ; {} ; {} ; } }
}
#[repr(C)] pub struct LLMQParams
{
    pub r#type : LLMQType, pub name : & 'static str, pub size : u32, pub
    min_size : u32, pub threshold : u32, pub dkg_params : DKGParams, pub
    signing_active_quorum_count : u32, pub keep_old_connections : u32, pub
    recovery_members : u32,
} #[doc = "FFI-representation of the"] #[doc = "LLMQParams"] #[repr(C)]
#[derive(Clone, Debug)] pub struct LLMQParamsFFI
{
    pub r#type : * mut LLMQTypeFFI, pub name : * mut std :: os :: raw ::
    c_char, pub size : u32, pub min_size : u32, pub threshold : u32, pub
    dkg_params : * mut DKGParamsFFI, pub signing_active_quorum_count : u32,
    pub keep_old_connections : u32, pub recovery_members : u32,
} impl rs_ffi_interfaces :: FFIConversion < LLMQParams > for LLMQParamsFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQParamsFFI) -> LLMQParams
    {
        let ffi_ref = & * ffi ; LLMQParams
        {
            r#type : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.r#type), name : rs_ffi_interfaces ::
            FFIConversion :: ffi_from(ffi_ref.name), size : ffi_ref.size,
            min_size : ffi_ref.min_size, threshold : ffi_ref.threshold,
            dkg_params : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.dkg_params), signing_active_quorum_count :
            ffi_ref.signing_active_quorum_count, keep_old_connections :
            ffi_ref.keep_old_connections, recovery_members :
            ffi_ref.recovery_members,
        }
    } unsafe fn ffi_to(obj : LLMQParams) -> * mut LLMQParamsFFI
    {
        rs_ffi_interfaces ::
        boxed(LLMQParamsFFI
        {
            r#type : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.r#type),
            name : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.name),
            size : obj.size, min_size : obj.min_size, threshold :
            obj.threshold, dkg_params : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.dkg_params), signing_active_quorum_count :
            obj.signing_active_quorum_count, keep_old_connections :
            obj.keep_old_connections, recovery_members : obj.recovery_members,
        })
    } unsafe fn destroy(ffi : * mut LLMQParamsFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQParamsFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < LLMQTypeFFI as rs_ffi_interfaces ::
            FFIConversion < LLMQType >> :: destroy(ffi_ref.r#type) ; < std ::
            os :: raw :: c_char as rs_ffi_interfaces :: FFIConversion < & str
            >> :: destroy(ffi_ref.name) ; {} ; {} ; {} ; < DKGParamsFFI as
            rs_ffi_interfaces :: FFIConversion < DKGParams >> ::
            destroy(ffi_ref.dkg_params) ; {} ; {} ; {} ;
        }
    }
}
#[warn(non_camel_case_types)] #[repr(C)] pub enum LLMQType
{
    LlmqtypeUnknown = 0, Llmqtype50_60 = 1, Llmqtype400_60 = 2, Llmqtype400_85
    = 3, Llmqtype100_67 = 4, Llmqtype60_75 = 5, Llmqtype25_67 = 6,
    LlmqtypeTest = 100, LlmqtypeDevnet = 101, LlmqtypeTestV17 = 102,
    LlmqtypeTestDIP0024 = 103, LlmqtypeTestInstantSend = 104,
    LlmqtypeDevnetDIP0024 = 105, LlmqtypeTestnetPlatform = 106,
    LlmqtypeDevnetPlatform = 107,
} #[doc = "FFI-representation of the"] #[doc = "LLMQType"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
LLMQTypeFFI
{
    LlmqtypeUnknown = 0, Llmqtype50_60 = 1, Llmqtype400_60 = 2, Llmqtype400_85
    = 3, Llmqtype100_67 = 4, Llmqtype60_75 = 5, Llmqtype25_67 = 6,
    LlmqtypeTest = 100, LlmqtypeDevnet = 101, LlmqtypeTestV17 = 102,
    LlmqtypeTestDIP0024 = 103, LlmqtypeTestInstantSend = 104,
    LlmqtypeDevnetDIP0024 = 105, LlmqtypeTestnetPlatform = 106,
    LlmqtypeDevnetPlatform = 107,
} impl rs_ffi_interfaces :: FFIConversion < LLMQType > for LLMQTypeFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQTypeFFI) -> LLMQType
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            LLMQTypeFFI :: LlmqtypeUnknown => LLMQType :: LlmqtypeUnknown,
            LLMQTypeFFI :: Llmqtype50_60 => LLMQType :: Llmqtype50_60,
            LLMQTypeFFI :: Llmqtype400_60 => LLMQType :: Llmqtype400_60,
            LLMQTypeFFI :: Llmqtype400_85 => LLMQType :: Llmqtype400_85,
            LLMQTypeFFI :: Llmqtype100_67 => LLMQType :: Llmqtype100_67,
            LLMQTypeFFI :: Llmqtype60_75 => LLMQType :: Llmqtype60_75,
            LLMQTypeFFI :: Llmqtype25_67 => LLMQType :: Llmqtype25_67,
            LLMQTypeFFI :: LlmqtypeTest => LLMQType :: LlmqtypeTest,
            LLMQTypeFFI :: LlmqtypeDevnet => LLMQType :: LlmqtypeDevnet,
            LLMQTypeFFI :: LlmqtypeTestV17 => LLMQType :: LlmqtypeTestV17,
            LLMQTypeFFI :: LlmqtypeTestDIP0024 => LLMQType ::
            LlmqtypeTestDIP0024, LLMQTypeFFI :: LlmqtypeTestInstantSend =>
            LLMQType :: LlmqtypeTestInstantSend, LLMQTypeFFI ::
            LlmqtypeDevnetDIP0024 => LLMQType :: LlmqtypeDevnetDIP0024,
            LLMQTypeFFI :: LlmqtypeTestnetPlatform => LLMQType ::
            LlmqtypeTestnetPlatform, LLMQTypeFFI :: LlmqtypeDevnetPlatform =>
            LLMQType :: LlmqtypeDevnetPlatform
        }
    } unsafe fn ffi_to(obj : LLMQType) -> * mut LLMQTypeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            LLMQType :: LlmqtypeUnknown => LLMQTypeFFI :: LlmqtypeUnknown,
            LLMQType :: Llmqtype50_60 => LLMQTypeFFI :: Llmqtype50_60,
            LLMQType :: Llmqtype400_60 => LLMQTypeFFI :: Llmqtype400_60,
            LLMQType :: Llmqtype400_85 => LLMQTypeFFI :: Llmqtype400_85,
            LLMQType :: Llmqtype100_67 => LLMQTypeFFI :: Llmqtype100_67,
            LLMQType :: Llmqtype60_75 => LLMQTypeFFI :: Llmqtype60_75,
            LLMQType :: Llmqtype25_67 => LLMQTypeFFI :: Llmqtype25_67,
            LLMQType :: LlmqtypeTest => LLMQTypeFFI :: LlmqtypeTest, LLMQType
            :: LlmqtypeDevnet => LLMQTypeFFI :: LlmqtypeDevnet, LLMQType ::
            LlmqtypeTestV17 => LLMQTypeFFI :: LlmqtypeTestV17, LLMQType ::
            LlmqtypeTestDIP0024 => LLMQTypeFFI :: LlmqtypeTestDIP0024,
            LLMQType :: LlmqtypeTestInstantSend => LLMQTypeFFI ::
            LlmqtypeTestInstantSend, LLMQType :: LlmqtypeDevnetDIP0024 =>
            LLMQTypeFFI :: LlmqtypeDevnetDIP0024, LLMQType ::
            LlmqtypeTestnetPlatform => LLMQTypeFFI :: LlmqtypeTestnetPlatform,
            LLMQType :: LlmqtypeDevnetPlatform => LLMQTypeFFI ::
            LlmqtypeDevnetPlatform
        })
    } unsafe fn destroy(ffi : * mut LLMQTypeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQTypeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                LLMQTypeFFI :: LlmqtypeUnknown => {}, LLMQTypeFFI ::
                Llmqtype50_60 => {}, LLMQTypeFFI :: Llmqtype400_60 => {},
                LLMQTypeFFI :: Llmqtype400_85 => {}, LLMQTypeFFI ::
                Llmqtype100_67 => {}, LLMQTypeFFI :: Llmqtype60_75 => {},
                LLMQTypeFFI :: Llmqtype25_67 => {}, LLMQTypeFFI ::
                LlmqtypeTest => {}, LLMQTypeFFI :: LlmqtypeDevnet => {},
                LLMQTypeFFI :: LlmqtypeTestV17 => {}, LLMQTypeFFI ::
                LlmqtypeTestDIP0024 => {}, LLMQTypeFFI ::
                LlmqtypeTestInstantSend => {}, LLMQTypeFFI ::
                LlmqtypeDevnetDIP0024 => {}, LLMQTypeFFI ::
                LlmqtypeTestnetPlatform => {}, LLMQTypeFFI ::
                LlmqtypeDevnetPlatform => {},
            }
        }
    }
}
pub struct Block { pub height : u32, pub hash : UInt256, }
#[doc = "FFI-representation of the"] #[doc = "Block"] #[repr(C)]
#[derive(Clone, Debug)] pub struct BlockFFI
{ pub height : u32, pub hash : * mut [u8 ; 32], } impl rs_ffi_interfaces ::
FFIConversion < Block > for BlockFFI
{
    unsafe fn ffi_from(ffi : * mut BlockFFI) -> Block
    {
        let ffi_ref = & * ffi ; Block
        {
            height : ffi_ref.height, hash : rs_ffi_interfaces :: FFIConversion
            :: ffi_from(ffi_ref.hash),
        }
    } unsafe fn ffi_to(obj : Block) -> * mut BlockFFI
    {
        rs_ffi_interfaces ::
        boxed(BlockFFI
        {
            height : obj.height, hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.hash),
        })
    } unsafe fn destroy(ffi : * mut BlockFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for BlockFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; {} ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> :: destroy(ffi_ref.hash) ;
        }
    }
}
#[repr(C)] pub enum LLMQSnapshotSkipMode
{ NoSkipping = 0, SkipFirst = 1, SkipExcept = 2, SkipAll = 3, }
#[doc = "FFI-representation of the"] #[doc = "LLMQSnapshotSkipMode"]
#[repr(C)] #[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub
enum LLMQSnapshotSkipModeFFI
{ NoSkipping = 0, SkipFirst = 1, SkipExcept = 2, SkipAll = 3, } impl
rs_ffi_interfaces :: FFIConversion < LLMQSnapshotSkipMode > for
LLMQSnapshotSkipModeFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQSnapshotSkipModeFFI) ->
    LLMQSnapshotSkipMode
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            LLMQSnapshotSkipModeFFI :: NoSkipping => LLMQSnapshotSkipMode ::
            NoSkipping, LLMQSnapshotSkipModeFFI :: SkipFirst =>
            LLMQSnapshotSkipMode :: SkipFirst, LLMQSnapshotSkipModeFFI ::
            SkipExcept => LLMQSnapshotSkipMode :: SkipExcept,
            LLMQSnapshotSkipModeFFI :: SkipAll => LLMQSnapshotSkipMode ::
            SkipAll
        }
    } unsafe fn ffi_to(obj : LLMQSnapshotSkipMode) -> * mut
    LLMQSnapshotSkipModeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            LLMQSnapshotSkipMode :: NoSkipping => LLMQSnapshotSkipModeFFI ::
            NoSkipping, LLMQSnapshotSkipMode :: SkipFirst =>
            LLMQSnapshotSkipModeFFI :: SkipFirst, LLMQSnapshotSkipMode ::
            SkipExcept => LLMQSnapshotSkipModeFFI :: SkipExcept,
            LLMQSnapshotSkipMode :: SkipAll => LLMQSnapshotSkipModeFFI ::
            SkipAll
        })
    } unsafe fn destroy(ffi : * mut LLMQSnapshotSkipModeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQSnapshotSkipModeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                LLMQSnapshotSkipModeFFI :: NoSkipping => {},
                LLMQSnapshotSkipModeFFI :: SkipFirst => {},
                LLMQSnapshotSkipModeFFI :: SkipExcept => {},
                LLMQSnapshotSkipModeFFI :: SkipAll => {},
            }
        }
    }
}
#[warn(non_camel_case_types)] #[repr(C)] pub enum LLMQVersion
{ Default = 1, Indexed = 2, BLSBasicDefault = 3, BLSBasicIndexed = 4, }
#[doc = "FFI-representation of the"] #[doc = "LLMQVersion"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
LLMQVersionFFI
{ Default = 1, Indexed = 2, BLSBasicDefault = 3, BLSBasicIndexed = 4, } impl
rs_ffi_interfaces :: FFIConversion < LLMQVersion > for LLMQVersionFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQVersionFFI) -> LLMQVersion
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            LLMQVersionFFI :: Default => LLMQVersion :: Default,
            LLMQVersionFFI :: Indexed => LLMQVersion :: Indexed,
            LLMQVersionFFI :: BLSBasicDefault => LLMQVersion ::
            BLSBasicDefault, LLMQVersionFFI :: BLSBasicIndexed => LLMQVersion
            :: BLSBasicIndexed
        }
    } unsafe fn ffi_to(obj : LLMQVersion) -> * mut LLMQVersionFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            LLMQVersion :: Default => LLMQVersionFFI :: Default, LLMQVersion
            :: Indexed => LLMQVersionFFI :: Indexed, LLMQVersion ::
            BLSBasicDefault => LLMQVersionFFI :: BLSBasicDefault, LLMQVersion
            :: BLSBasicIndexed => LLMQVersionFFI :: BLSBasicIndexed
        })
    } unsafe fn destroy(ffi : * mut LLMQVersionFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQVersionFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                LLMQVersionFFI :: Default => {}, LLMQVersionFFI :: Indexed =>
                {}, LLMQVersionFFI :: BLSBasicDefault => {}, LLMQVersionFFI ::
                BLSBasicIndexed => {},
            }
        }
    }
}
#[repr(C)] pub struct SocketAddress
{ pub ip_address : UInt128, pub port : u16, }
#[doc = "FFI-representation of the"] #[doc = "SocketAddress"] #[repr(C)]
#[derive(Clone, Debug)] pub struct SocketAddressFFI
{ pub ip_address : * mut [u8 ; 16], pub port : u16, } impl rs_ffi_interfaces
:: FFIConversion < SocketAddress > for SocketAddressFFI
{
    unsafe fn ffi_from(ffi : * mut SocketAddressFFI) -> SocketAddress
    {
        let ffi_ref = & * ffi ; SocketAddress
        {
            ip_address : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.ip_address), port : ffi_ref.port,
        }
    } unsafe fn ffi_to(obj : SocketAddress) -> * mut SocketAddressFFI
    {
        rs_ffi_interfaces ::
        boxed(SocketAddressFFI
        {
            ip_address : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.ip_address), port : obj.port,
        })
    } unsafe fn destroy(ffi : * mut SocketAddressFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for SocketAddressFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 16] as rs_ffi_interfaces ::
            FFIConversion < UInt128 >> :: destroy(ffi_ref.ip_address) ; {} ;
        }
    }
}
#[repr(u16)] pub enum MasternodeType { Regular = 0, HighPerformance = 1, }
#[doc = "FFI-representation of the"] #[doc = "MasternodeType"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
MasternodeTypeFFI { Regular = 0, HighPerformance = 1, } impl rs_ffi_interfaces
:: FFIConversion < MasternodeType > for MasternodeTypeFFI
{
    unsafe fn ffi_from(ffi : * mut MasternodeTypeFFI) -> MasternodeType
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            MasternodeTypeFFI :: Regular => MasternodeType :: Regular,
            MasternodeTypeFFI :: HighPerformance => MasternodeType ::
            HighPerformance
        }
    } unsafe fn ffi_to(obj : MasternodeType) -> * mut MasternodeTypeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            MasternodeType :: Regular => MasternodeTypeFFI :: Regular,
            MasternodeType :: HighPerformance => MasternodeTypeFFI ::
            HighPerformance
        })
    } unsafe fn destroy(ffi : * mut MasternodeTypeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for MasternodeTypeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                MasternodeTypeFFI :: Regular => {}, MasternodeTypeFFI ::
                HighPerformance => {},
            }
        }
    }
}
pub struct UInt128(pub [u8 ; 16]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt128 > for [u8 ; 16]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 16]) -> UInt128
    { let ffi_ref = * ffi ; UInt128(ffi_ref) } unsafe fn ffi_to(obj : UInt128)
    -> * mut [u8 ; 16] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 16]) { ; }
}
pub struct UInt160(pub [u8 ; 20]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt160 > for [u8 ; 20]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 20]) -> UInt160
    { let ffi_ref = * ffi ; UInt160(ffi_ref) } unsafe fn ffi_to(obj : UInt160)
    -> * mut [u8 ; 20] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 20]) { ; }
}
pub struct UInt256(pub [u8 ; 32]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt256 > for [u8 ; 32]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 32]) -> UInt256
    { let ffi_ref = * ffi ; UInt256(ffi_ref) } unsafe fn ffi_to(obj : UInt256)
    -> * mut [u8 ; 32] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 32]) { ; }
}
pub struct UInt384(pub [u8 ; 48]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt384 > for [u8 ; 48]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 48]) -> UInt384
    { let ffi_ref = * ffi ; UInt384(ffi_ref) } unsafe fn ffi_to(obj : UInt384)
    -> * mut [u8 ; 48] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 48]) { ; }
}
pub struct UInt512(pub [u8 ; 64]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt512 > for [u8 ; 64]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 64]) -> UInt512
    { let ffi_ref = * ffi ; UInt512(ffi_ref) } unsafe fn ffi_to(obj : UInt512)
    -> * mut [u8 ; 64] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 64]) { ; }
}
pub struct UInt768(pub [u8 ; 96]) ; impl rs_ffi_interfaces :: FFIConversion <
UInt768 > for [u8 ; 96]
{
    unsafe fn ffi_from(ffi : * mut [u8 ; 96]) -> UInt768
    { let ffi_ref = * ffi ; UInt768(ffi_ref) } unsafe fn ffi_to(obj : UInt768)
    -> * mut [u8 ; 96] { rs_ffi_interfaces :: boxed(obj.0) } unsafe fn
    destroy(ffi : * mut [u8 ; 96]) { ; }
}
pub type AddInsightCallback =
fn(block_hash : UInt256, context : rs_ffi_interfaces :: OpaqueContext) ; pub
type AddInsightCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], context : rs_ffi_interfaces ::
OpaqueContextFFI) ;
pub type ShouldProcessDiffWithRangeCallback =
fn(base_block_hash : UInt256, block_hash : UInt256, context :
rs_ffi_interfaces :: OpaqueContext) -> crate :: processing :: processing_error
:: ProcessingError ; pub type ShouldProcessDiffWithRangeCallbackFFI = unsafe
extern "C"
fn(base_block_hash : * mut [u8 ; 32], block_hash : * mut [u8 ; 32], context :
rs_ffi_interfaces :: OpaqueContextFFI) -> * mut crate :: processing ::
processing_error :: ProcessingErrorFFI ;
pub type GetBlockHeightByHashCallback =
fn(block_hash : UInt256, context : rs_ffi_interfaces :: OpaqueContext) -> u32
; pub type GetBlockHeightByHashCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], context : rs_ffi_interfaces ::
OpaqueContextFFI) -> u32 ;
pub type GetBlockHashByHeightCallback =
fn(block_height : u32, context : rs_ffi_interfaces :: OpaqueContext) ->
UInt256 ; pub type GetBlockHashByHeightCallbackFFI = unsafe extern "C"
fn(block_height : u32, context : rs_ffi_interfaces :: OpaqueContextFFI) -> *
mut [u8 ; 32] ;
pub type GetMerkleRootCallback =
fn(block_hash : UInt256, context : rs_ffi_interfaces :: OpaqueContext) ->
UInt256 ; pub type GetMerkleRootCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], context : rs_ffi_interfaces ::
OpaqueContextFFI) -> * mut [u8 ; 32] ;
pub type GetMasternodeListCallback =
fn(block_hash : UInt256, context : rs_ffi_interfaces :: OpaqueContext) ->
crate :: models :: masternode_list :: MasternodeList ; pub type
GetMasternodeListCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], context : rs_ffi_interfaces ::
OpaqueContextFFI) -> * mut crate :: models :: masternode_list ::
MasternodeListFFI ;
pub type DestroyMasternodeListCallback =
fn(masternode_list : crate :: models :: masternode_list :: MasternodeList) ;
pub type DestroyMasternodeListCallbackFFI = unsafe extern "C"
fn(masternode_list : * mut crate :: models :: masternode_list ::
MasternodeListFFI) ;
pub type SaveMasternodeListCallback =
fn(block_hash : UInt256, masternode_list : crate :: models :: masternode_list
:: MasternodeList, context : rs_ffi_interfaces :: OpaqueContext) -> bool ; pub
type SaveMasternodeListCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], masternode_list : * mut crate :: models ::
masternode_list :: MasternodeListFFI, context : rs_ffi_interfaces ::
OpaqueContextFFI) -> bool ;
pub type GetLLMQSnapshotByBlockHashCallback =
fn(block_hash : UInt256, context : rs_ffi_interfaces :: OpaqueContext) ->
crate :: models :: snapshot :: LLMQSnapshot ; pub type
GetLLMQSnapshotByBlockHashCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], context : rs_ffi_interfaces ::
OpaqueContextFFI) -> * mut crate :: models :: snapshot :: LLMQSnapshotFFI ;
pub type SaveLLMQSnapshotCallback =
fn(block_hash : UInt256, snapshot : crate :: models :: snapshot ::
LLMQSnapshot, context : rs_ffi_interfaces :: OpaqueContext) -> bool ; pub type
SaveLLMQSnapshotCallbackFFI = unsafe extern "C"
fn(block_hash : * mut [u8 ; 32], snapshot : * mut crate :: models :: snapshot
:: LLMQSnapshotFFI, context : rs_ffi_interfaces :: OpaqueContextFFI) -> bool ;
pub type DestroyHashCallback = fn(hash : UInt256) ; pub type
DestroyHashCallbackFFI = unsafe extern "C" fn(hash : * mut [u8 ; 32]) ;
pub type DestroyLLMQSnapshotCallback =
fn(snapshot : crate :: models :: snapshot :: LLMQSnapshot) ; pub type
DestroyLLMQSnapshotCallbackFFI = unsafe extern "C"
fn(snapshot : * mut crate :: models :: snapshot :: LLMQSnapshotFFI) ;
pub struct LLMQEntry
{
    pub version : crate :: common :: llmq_version :: LLMQVersion, pub
    llmq_hash : UInt256, pub index : Option < u16 >, pub public_key : UInt384,
    pub threshold_signature : UInt768, pub verification_vector_hash : UInt256,
    pub all_commitment_aggregated_signature : UInt768, pub llmq_type : crate
    :: chain :: common :: llmq_type :: LLMQType, pub signers_bitset : Vec < u8
    >, pub signers_count : VarInt, pub valid_members_bitset : Vec < u8 >, pub
    valid_members_count : VarInt, pub entry_hash : UInt256, pub verified :
    bool, pub saved : bool, pub commitment_hash : Option < UInt256 >,
} #[doc = "FFI-representation of the"] #[doc = "LLMQEntry"] #[repr(C)]
#[derive(Clone, Debug)] pub struct LLMQEntryFFI
{
    pub version : * mut crate :: common :: llmq_version :: LLMQVersionFFI, pub
    llmq_hash : * mut [u8 ; 32], pub index : u16, pub public_key : * mut
    [u8 ; 48], pub threshold_signature : * mut [u8 ; 96], pub
    verification_vector_hash : * mut [u8 ; 32], pub
    all_commitment_aggregated_signature : * mut [u8 ; 96], pub llmq_type : *
    mut crate :: chain :: common :: llmq_type :: LLMQTypeFFI, pub
    signers_bitset : * mut rs_ffi_interfaces :: VecFFI < u8 >, pub
    signers_count : u64, pub valid_members_bitset : * mut rs_ffi_interfaces ::
    VecFFI < u8 >, pub valid_members_count : u64, pub entry_hash : * mut
    [u8 ; 32], pub verified : bool, pub saved : bool, pub commitment_hash : *
    mut [u8 ; 32],
} impl rs_ffi_interfaces :: FFIConversion < LLMQEntry > for LLMQEntryFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQEntryFFI) -> LLMQEntry
    {
        let ffi_ref = & * ffi ; LLMQEntry
        {
            version : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.version), llmq_hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_from(ffi_ref.llmq_hash), index :
            (ffi_ref.index > 0).then_some(ffi_ref.index), public_key :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.public_key), threshold_signature :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.threshold_signature), verification_vector_hash :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.verification_vector_hash),
            all_commitment_aggregated_signature : rs_ffi_interfaces ::
            FFIConversion ::
            ffi_from(ffi_ref.all_commitment_aggregated_signature), llmq_type :
            rs_ffi_interfaces :: FFIConversion :: ffi_from(ffi_ref.llmq_type),
            signers_bitset :
            {
                let vec = & * ffi_ref.signers_bitset ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }, signers_count : VarInt(ffi_ref.signers_count),
            valid_members_bitset :
            {
                let vec = & * ffi_ref.valid_members_bitset ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }, valid_members_count : VarInt(ffi_ref.valid_members_count),
            entry_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.entry_hash), verified : ffi_ref.verified, saved :
            ffi_ref.saved, commitment_hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_from_opt(ffi_ref.commitment_hash),
        }
    } unsafe fn ffi_to(obj : LLMQEntry) -> * mut LLMQEntryFFI
    {
        rs_ffi_interfaces ::
        boxed(LLMQEntryFFI
        {
            version : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.version), llmq_hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.llmq_hash), index :
            obj.index.unwrap_or(0), public_key : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.public_key), threshold_signature :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.threshold_signature), verification_vector_hash :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.verification_vector_hash),
            all_commitment_aggregated_signature : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.all_commitment_aggregated_signature),
            llmq_type : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.llmq_type), signers_bitset : rs_ffi_interfaces ::
            boxed({
                let vec = obj.signers_bitset ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.clone())
                }
            }), signers_count : obj.signers_count.0, valid_members_bitset :
            rs_ffi_interfaces ::
            boxed({
                let vec = obj.valid_members_bitset ; rs_ffi_interfaces ::
                VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.clone())
                }
            }), valid_members_count : obj.valid_members_count.0, entry_hash :
            rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.entry_hash),
            verified : obj.verified, saved : obj.saved, commitment_hash :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.commitment_hash),
        })
    } unsafe fn destroy(ffi : * mut LLMQEntryFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQEntryFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < crate :: common :: llmq_version ::
            LLMQVersionFFI as rs_ffi_interfaces :: FFIConversion < crate ::
            common :: llmq_version :: LLMQVersion >> ::
            destroy(ffi_ref.version) ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> :: destroy(ffi_ref.llmq_hash) ; {} ; <
            [u8 ; 48] as rs_ffi_interfaces :: FFIConversion < UInt384 >> ::
            destroy(ffi_ref.public_key) ; < [u8 ; 96] as rs_ffi_interfaces ::
            FFIConversion < UInt768 >> :: destroy(ffi_ref.threshold_signature)
            ; < [u8 ; 32] as rs_ffi_interfaces :: FFIConversion < UInt256 >>
            :: destroy(ffi_ref.verification_vector_hash) ; < [u8 ; 96] as
            rs_ffi_interfaces :: FFIConversion < UInt768 >> ::
            destroy(ffi_ref.all_commitment_aggregated_signature) ; < crate ::
            chain :: common :: llmq_type :: LLMQTypeFFI as rs_ffi_interfaces
            :: FFIConversion < crate :: chain :: common :: llmq_type ::
            LLMQType >> :: destroy(ffi_ref.llmq_type) ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.signers_bitset) ; ; {} ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.valid_members_bitset) ; ; {} ; < [u8 ; 32] as
            rs_ffi_interfaces :: FFIConversion < UInt256 >> ::
            destroy(ffi_ref.entry_hash) ; {} ; {} ; if!
            ffi_ref.commitment_hash.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.commitment_hash) ; } ;
        }
    }
}
pub struct LLMQTypedHash
{
    pub r#type : crate :: chain :: common :: llmq_type :: LLMQType, pub hash :
    UInt256,
} #[doc = "FFI-representation of the"] #[doc = "LLMQTypedHash"] #[repr(C)]
#[derive(Clone, Debug)] pub struct LLMQTypedHashFFI
{
    pub r#type : * mut crate :: chain :: common :: llmq_type :: LLMQTypeFFI,
    pub hash : * mut [u8 ; 32],
} impl rs_ffi_interfaces :: FFIConversion < LLMQTypedHash > for
LLMQTypedHashFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQTypedHashFFI) -> LLMQTypedHash
    {
        let ffi_ref = & * ffi ; LLMQTypedHash
        {
            r#type : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.r#type), hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_from(ffi_ref.hash),
        }
    } unsafe fn ffi_to(obj : LLMQTypedHash) -> * mut LLMQTypedHashFFI
    {
        rs_ffi_interfaces ::
        boxed(LLMQTypedHashFFI
        {
            r#type : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.r#type),
            hash : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.hash),
        })
    } unsafe fn destroy(ffi : * mut LLMQTypedHashFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQTypedHashFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < crate :: chain :: common :: llmq_type ::
            LLMQTypeFFI as rs_ffi_interfaces :: FFIConversion < crate :: chain
            :: common :: llmq_type :: LLMQType >> :: destroy(ffi_ref.r#type) ;
            < [u8 ; 32] as rs_ffi_interfaces :: FFIConversion < UInt256 >> ::
            destroy(ffi_ref.hash) ;
        }
    }
}
pub struct LLMQIndexedHash { pub index : u32, pub hash : UInt256, }
#[doc = "FFI-representation of the"] #[doc = "LLMQIndexedHash"] #[repr(C)]
#[derive(Clone, Debug)] pub struct LLMQIndexedHashFFI
{ pub index : u32, pub hash : * mut [u8 ; 32], } impl rs_ffi_interfaces ::
FFIConversion < LLMQIndexedHash > for LLMQIndexedHashFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQIndexedHashFFI) -> LLMQIndexedHash
    {
        let ffi_ref = & * ffi ; LLMQIndexedHash
        {
            index : ffi_ref.index, hash : rs_ffi_interfaces :: FFIConversion
            :: ffi_from(ffi_ref.hash),
        }
    } unsafe fn ffi_to(obj : LLMQIndexedHash) -> * mut LLMQIndexedHashFFI
    {
        rs_ffi_interfaces ::
        boxed(LLMQIndexedHashFFI
        {
            index : obj.index, hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.hash),
        })
    } unsafe fn destroy(ffi : * mut LLMQIndexedHashFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQIndexedHashFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; {} ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> :: destroy(ffi_ref.hash) ;
        }
    }
}
pub struct MasternodeEntry
{
    pub provider_registration_transaction_hash : UInt256, pub confirmed_hash :
    UInt256, pub
    confirmed_hash_hashed_with_provider_registration_transaction_hash : Option
    < UInt256 >, pub socket_address : crate :: common :: socket_address ::
    SocketAddress, pub operator_public_key : crate :: models ::
    operator_public_key :: OperatorPublicKey, pub
    previous_operator_public_keys : BTreeMap < crate :: common :: block ::
    Block, crate :: models :: operator_public_key :: OperatorPublicKey >, pub
    previous_entry_hashes : BTreeMap < crate :: common :: block :: Block,
    UInt256 >, pub previous_validity : BTreeMap < crate :: common :: block ::
    Block, bool >, pub known_confirmed_at_height : Option < u32 >, pub
    update_height : u32, pub key_id_voting : UInt160, pub is_valid : bool, pub
    mn_type : crate :: common :: masternode_type :: MasternodeType, pub
    platform_http_port : u16, pub platform_node_id : UInt160, pub entry_hash :
    UInt256,
} #[doc = "FFI-representation of the"] #[doc = "MasternodeEntry"] #[repr(C)]
#[derive(Clone, Debug)] pub struct MasternodeEntryFFI
{
    pub provider_registration_transaction_hash : * mut [u8 ; 32], pub
    confirmed_hash : * mut [u8 ; 32], pub
    confirmed_hash_hashed_with_provider_registration_transaction_hash : * mut
    [u8 ; 32], pub socket_address : * mut crate :: common :: socket_address ::
    SocketAddressFFI, pub operator_public_key : * mut crate :: models ::
    operator_public_key :: OperatorPublicKeyFFI, pub
    previous_operator_public_keys : * mut rs_ffi_interfaces :: MapFFI < * mut
    crate :: common :: block :: BlockFFI, * mut crate :: models ::
    operator_public_key :: OperatorPublicKeyFFI >, pub previous_entry_hashes :
    * mut rs_ffi_interfaces :: MapFFI < * mut crate :: common :: block ::
    BlockFFI, * mut [u8 ; 32] >, pub previous_validity : * mut
    rs_ffi_interfaces :: MapFFI < * mut crate :: common :: block :: BlockFFI,
    bool >, pub known_confirmed_at_height : u32, pub update_height : u32, pub
    key_id_voting : * mut [u8 ; 20], pub is_valid : bool, pub mn_type : * mut
    crate :: common :: masternode_type :: MasternodeTypeFFI, pub
    platform_http_port : u16, pub platform_node_id : * mut [u8 ; 20], pub
    entry_hash : * mut [u8 ; 32],
} impl rs_ffi_interfaces :: FFIConversion < MasternodeEntry > for
MasternodeEntryFFI
{
    unsafe fn ffi_from(ffi : * mut MasternodeEntryFFI) -> MasternodeEntry
    {
        let ffi_ref = & * ffi ; MasternodeEntry
        {
            provider_registration_transaction_hash : rs_ffi_interfaces ::
            FFIConversion ::
            ffi_from(ffi_ref.provider_registration_transaction_hash),
            confirmed_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.confirmed_hash),
            confirmed_hash_hashed_with_provider_registration_transaction_hash
            : rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.confirmed_hash_hashed_with_provider_registration_transaction_hash),
            socket_address : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.socket_address), operator_public_key :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.operator_public_key),
            previous_operator_public_keys :
            {
                let map = & * ffi_ref.previous_operator_public_keys ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, previous_entry_hashes :
            {
                let map = & * ffi_ref.previous_entry_hashes ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, previous_validity :
            {
                let map = & * ffi_ref.previous_validity ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = *
                    map.values.add(i) ; acc.insert(key, value) ; acc
                })
            }, known_confirmed_at_height :
            (ffi_ref.known_confirmed_at_height >
            0).then_some(ffi_ref.known_confirmed_at_height), update_height :
            ffi_ref.update_height, key_id_voting : rs_ffi_interfaces ::
            FFIConversion :: ffi_from(ffi_ref.key_id_voting), is_valid :
            ffi_ref.is_valid, mn_type : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.mn_type), platform_http_port :
            ffi_ref.platform_http_port, platform_node_id : rs_ffi_interfaces
            :: FFIConversion :: ffi_from(ffi_ref.platform_node_id), entry_hash
            : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.entry_hash),
        }
    } unsafe fn ffi_to(obj : MasternodeEntry) -> * mut MasternodeEntryFFI
    {
        rs_ffi_interfaces ::
        boxed(MasternodeEntryFFI
        {
            provider_registration_transaction_hash : rs_ffi_interfaces ::
            FFIConversion ::
            ffi_to(obj.provider_registration_transaction_hash), confirmed_hash
            : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.confirmed_hash),
            confirmed_hash_hashed_with_provider_registration_transaction_hash
            : rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.confirmed_hash_hashed_with_provider_registration_transaction_hash),
            socket_address : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.socket_address), operator_public_key :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.operator_public_key), previous_operator_public_keys :
            rs_ffi_interfaces ::
            boxed({
                let map = obj.previous_operator_public_keys ;
                rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), previous_entry_hashes : rs_ffi_interfaces ::
            boxed({
                let map = obj.previous_entry_hashes ; rs_ffi_interfaces ::
                MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), previous_validity : rs_ffi_interfaces ::
            boxed({
                let map = obj.previous_validity ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | o).collect())
                }
            }), known_confirmed_at_height :
            obj.known_confirmed_at_height.unwrap_or(0), update_height :
            obj.update_height, key_id_voting : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.key_id_voting), is_valid :
            obj.is_valid, mn_type : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.mn_type), platform_http_port : obj.platform_http_port,
            platform_node_id : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.platform_node_id), entry_hash : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.entry_hash),
        })
    } unsafe fn destroy(ffi : * mut MasternodeEntryFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for MasternodeEntryFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> ::
            destroy(ffi_ref.provider_registration_transaction_hash) ; <
            [u8 ; 32] as rs_ffi_interfaces :: FFIConversion < UInt256 >> ::
            destroy(ffi_ref.confirmed_hash) ; if!
            ffi_ref.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null()
            {
                rs_ffi_interfaces ::
                unbox_any(ffi_ref.confirmed_hash_hashed_with_provider_registration_transaction_hash)
                ;
            } ; < crate :: common :: socket_address :: SocketAddressFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: common ::
            socket_address :: SocketAddress >> ::
            destroy(ffi_ref.socket_address) ; < crate :: models ::
            operator_public_key :: OperatorPublicKeyFFI as rs_ffi_interfaces
            :: FFIConversion < crate :: models :: operator_public_key ::
            OperatorPublicKey >> :: destroy(ffi_ref.operator_public_key) ;
            rs_ffi_interfaces ::
            unbox_any(ffi_ref.previous_operator_public_keys) ; ;
            rs_ffi_interfaces :: unbox_any(ffi_ref.previous_entry_hashes) ; ;
            rs_ffi_interfaces :: unbox_any(ffi_ref.previous_validity) ; ; {} ;
            {} ; < [u8 ; 20] as rs_ffi_interfaces :: FFIConversion < UInt160
            >> :: destroy(ffi_ref.key_id_voting) ; {} ; < crate :: common ::
            masternode_type :: MasternodeTypeFFI as rs_ffi_interfaces ::
            FFIConversion < crate :: common :: masternode_type ::
            MasternodeType >> :: destroy(ffi_ref.mn_type) ; {} ; < [u8 ; 20]
            as rs_ffi_interfaces :: FFIConversion < UInt160 >> ::
            destroy(ffi_ref.platform_node_id) ; < [u8 ; 32] as
            rs_ffi_interfaces :: FFIConversion < UInt256 >> ::
            destroy(ffi_ref.entry_hash) ;
        }
    }
}
pub struct MasternodeList
{
    pub block_hash : UInt256, pub known_height : u32, pub
    masternode_merkle_root : Option < UInt256 >, pub llmq_merkle_root : Option
    < UInt256 >, pub masternodes : BTreeMap < UInt256, crate :: models ::
    masternode_entry :: MasternodeEntry >, pub quorums : BTreeMap < crate ::
    chain :: common :: llmq_type :: LLMQType, BTreeMap < UInt256, crate ::
    models :: llmq_entry :: LLMQEntry > >,
} #[doc = "FFI-representation of the"] #[doc = "MasternodeList"] #[repr(C)]
#[derive(Clone, Debug)] pub struct MasternodeListFFI
{
    pub block_hash : * mut [u8 ; 32], pub known_height : u32, pub
    masternode_merkle_root : * mut [u8 ; 32], pub llmq_merkle_root : * mut
    [u8 ; 32], pub masternodes : * mut rs_ffi_interfaces :: MapFFI < * mut
    [u8 ; 32], * mut crate :: models :: masternode_entry :: MasternodeEntryFFI
    >, pub quorums : * mut rs_ffi_interfaces :: MapFFI < * mut crate :: chain
    :: common :: llmq_type :: LLMQTypeFFI, * mut rs_ffi_interfaces :: MapFFI <
    * mut [u8 ; 32], * mut crate :: models :: llmq_entry :: LLMQEntryFFI > >,
} impl rs_ffi_interfaces :: FFIConversion < MasternodeList > for
MasternodeListFFI
{
    unsafe fn ffi_from(ffi : * mut MasternodeListFFI) -> MasternodeList
    {
        let ffi_ref = & * ffi ; MasternodeList
        {
            block_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.block_hash), known_height : ffi_ref.known_height,
            masternode_merkle_root : rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.masternode_merkle_root), llmq_merkle_root :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.llmq_merkle_root), masternodes :
            {
                let map = & * ffi_ref.masternodes ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                    :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                    acc.insert(key, value) ; acc
                })
            }, quorums :
            {
                let map = & * ffi_ref.quorums ;
                (0 ..
                map.count).fold(BTreeMap :: new(), | mut acc, i |
                {
                    let key = rs_ffi_interfaces :: FFIConversion ::
                    ffi_from(* map.keys.add(i)) ; let value =
                    {
                        let map = & * ((* map.values.add(i))) ;
                        (0 ..
                        map.count).fold(BTreeMap :: new(), | mut acc, i |
                        {
                            let key = rs_ffi_interfaces :: FFIConversion ::
                            ffi_from(* map.keys.add(i)) ; let value = rs_ffi_interfaces
                            :: FFIConversion :: ffi_from(* map.values.add(i)) ;
                            acc.insert(key, value) ; acc
                        })
                    } ; acc.insert(key, value) ; acc
                })
            },
        }
    } unsafe fn ffi_to(obj : MasternodeList) -> * mut MasternodeListFFI
    {
        rs_ffi_interfaces ::
        boxed(MasternodeListFFI
        {
            block_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.block_hash), known_height : obj.known_height,
            masternode_merkle_root : rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.masternode_merkle_root), llmq_merkle_root :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.llmq_merkle_root), masternodes : rs_ffi_interfaces
            ::
            boxed({
                let map = obj.masternodes ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    :: FFIConversion :: ffi_to(o)).collect())
                }
            }), quorums : rs_ffi_interfaces ::
            boxed({
                let map = obj.quorums ; rs_ffi_interfaces :: MapFFI
                {
                    count : map.len(), keys : rs_ffi_interfaces ::
                    boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect()), values :
                    rs_ffi_interfaces ::
                    boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                    ::
                    boxed({
                        let map = o ; rs_ffi_interfaces :: MapFFI
                        {
                            count : map.len(), keys : rs_ffi_interfaces ::
                            boxed_vec(map.keys().cloned().map(| o | rs_ffi_interfaces ::
                            FFIConversion :: ffi_to(o)).collect()), values :
                            rs_ffi_interfaces ::
                            boxed_vec(map.values().cloned().map(| o | rs_ffi_interfaces
                            :: FFIConversion :: ffi_to(o)).collect())
                        }
                    })).collect())
                }
            }),
        })
    } unsafe fn destroy(ffi : * mut MasternodeListFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for MasternodeListFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> :: destroy(ffi_ref.block_hash) ; {} ;
            if! ffi_ref.masternode_merkle_root.is_null()
            {
                rs_ffi_interfaces :: unbox_any(ffi_ref.masternode_merkle_root)
                ;
            } ; if! ffi_ref.llmq_merkle_root.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.llmq_merkle_root) ; } ;
            rs_ffi_interfaces :: unbox_any(ffi_ref.masternodes) ; ;
            rs_ffi_interfaces :: unbox_any(ffi_ref.quorums) ; ;
        }
    }
}
pub struct OperatorPublicKey { pub data : UInt384, pub version : u16, }
#[doc = "FFI-representation of the"] #[doc = "OperatorPublicKey"] #[repr(C)]
#[derive(Clone, Debug)] pub struct OperatorPublicKeyFFI
{ pub data : * mut [u8 ; 48], pub version : u16, } impl rs_ffi_interfaces ::
FFIConversion < OperatorPublicKey > for OperatorPublicKeyFFI
{
    unsafe fn ffi_from(ffi : * mut OperatorPublicKeyFFI) -> OperatorPublicKey
    {
        let ffi_ref = & * ffi ; OperatorPublicKey
        {
            data : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.data), version : ffi_ref.version,
        }
    } unsafe fn ffi_to(obj : OperatorPublicKey) -> * mut OperatorPublicKeyFFI
    {
        rs_ffi_interfaces ::
        boxed(OperatorPublicKeyFFI
        {
            data : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.data),
            version : obj.version,
        })
    } unsafe fn destroy(ffi : * mut OperatorPublicKeyFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for OperatorPublicKeyFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 48] as rs_ffi_interfaces ::
            FFIConversion < UInt384 >> :: destroy(ffi_ref.data) ; {} ;
        }
    }
}
pub struct QuorumsCLSigsObject
{ pub signature : UInt768, pub index_set : Vec < u16 >, }
#[doc = "FFI-representation of the"] #[doc = "QuorumsCLSigsObject"] #[repr(C)]
#[derive(Clone, Debug)] pub struct QuorumsCLSigsObjectFFI
{
    pub signature : * mut [u8 ; 96], pub index_set : * mut rs_ffi_interfaces
    :: VecFFI < u16 >,
} impl rs_ffi_interfaces :: FFIConversion < QuorumsCLSigsObject > for
QuorumsCLSigsObjectFFI
{
    unsafe fn ffi_from(ffi : * mut QuorumsCLSigsObjectFFI) ->
    QuorumsCLSigsObject
    {
        let ffi_ref = & * ffi ; QuorumsCLSigsObject
        {
            signature : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.signature), index_set :
            {
                let vec = & * ffi_ref.index_set ; std :: slice ::
                from_raw_parts(vec.values as * const u16, vec.count).to_vec()
            },
        }
    } unsafe fn ffi_to(obj : QuorumsCLSigsObject) -> * mut
    QuorumsCLSigsObjectFFI
    {
        rs_ffi_interfaces ::
        boxed(QuorumsCLSigsObjectFFI
        {
            signature : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.signature), index_set : rs_ffi_interfaces ::
            boxed({
                let vec = obj.index_set ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.clone())
                }
            }),
        })
    } unsafe fn destroy(ffi : * mut QuorumsCLSigsObjectFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for QuorumsCLSigsObjectFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 96] as rs_ffi_interfaces ::
            FFIConversion < UInt768 >> :: destroy(ffi_ref.signature) ;
            rs_ffi_interfaces :: unbox_any(ffi_ref.index_set) ; ;
        }
    }
}
pub struct LLMQSnapshot
{
    pub member_list : Vec < u8 >, pub skip_list : Vec < i32 >, pub
    skip_list_mode : crate :: common :: llmq_snapshot_skip_mode ::
    LLMQSnapshotSkipMode,
} #[doc = "FFI-representation of the"] #[doc = "LLMQSnapshot"] #[repr(C)]
#[derive(Clone, Debug)] pub struct LLMQSnapshotFFI
{
    pub member_list : * mut rs_ffi_interfaces :: VecFFI < u8 >, pub skip_list
    : * mut rs_ffi_interfaces :: VecFFI < i32 >, pub skip_list_mode : * mut
    crate :: common :: llmq_snapshot_skip_mode :: LLMQSnapshotSkipModeFFI,
} impl rs_ffi_interfaces :: FFIConversion < LLMQSnapshot > for LLMQSnapshotFFI
{
    unsafe fn ffi_from(ffi : * mut LLMQSnapshotFFI) -> LLMQSnapshot
    {
        let ffi_ref = & * ffi ; LLMQSnapshot
        {
            member_list :
            {
                let vec = & * ffi_ref.member_list ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }, skip_list :
            {
                let vec = & * ffi_ref.skip_list ; std :: slice ::
                from_raw_parts(vec.values as * const i32, vec.count).to_vec()
            }, skip_list_mode : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.skip_list_mode),
        }
    } unsafe fn ffi_to(obj : LLMQSnapshot) -> * mut LLMQSnapshotFFI
    {
        rs_ffi_interfaces ::
        boxed(LLMQSnapshotFFI
        {
            member_list : rs_ffi_interfaces ::
            boxed({
                let vec = obj.member_list ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.clone())
                }
            }), skip_list : rs_ffi_interfaces ::
            boxed({
                let vec = obj.skip_list ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.clone())
                }
            }), skip_list_mode : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.skip_list_mode),
        })
    } unsafe fn destroy(ffi : * mut LLMQSnapshotFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for LLMQSnapshotFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.member_list) ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.skip_list) ; ; < crate :: common ::
            llmq_snapshot_skip_mode :: LLMQSnapshotSkipModeFFI as
            rs_ffi_interfaces :: FFIConversion < crate :: common ::
            llmq_snapshot_skip_mode :: LLMQSnapshotSkipMode >> ::
            destroy(ffi_ref.skip_list_mode) ;
        }
    }
}
pub struct CoinbaseTransaction
{
    pub base : crate :: tx :: transaction :: Transaction, pub
    coinbase_transaction_version : u16, pub height : u32, pub
    merkle_root_mn_list : UInt256, pub merkle_root_llmq_list : Option <
    UInt256 >, pub best_cl_height_diff : u32, pub best_cl_signature : Option <
    UInt768 >,
} #[doc = "FFI-representation of the"] #[doc = "CoinbaseTransaction"]
#[repr(C)] #[derive(Clone, Debug)] pub struct CoinbaseTransactionFFI
{
    pub base : * mut crate :: tx :: transaction :: TransactionFFI, pub
    coinbase_transaction_version : u16, pub height : u32, pub
    merkle_root_mn_list : * mut [u8 ; 32], pub merkle_root_llmq_list : * mut
    [u8 ; 32], pub best_cl_height_diff : u32, pub best_cl_signature : * mut
    [u8 ; 96],
} impl rs_ffi_interfaces :: FFIConversion < CoinbaseTransaction > for
CoinbaseTransactionFFI
{
    unsafe fn ffi_from(ffi : * mut CoinbaseTransactionFFI) ->
    CoinbaseTransaction
    {
        let ffi_ref = & * ffi ; CoinbaseTransaction
        {
            base : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.base), coinbase_transaction_version :
            ffi_ref.coinbase_transaction_version, height : ffi_ref.height,
            merkle_root_mn_list : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.merkle_root_mn_list), merkle_root_llmq_list :
            rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.merkle_root_llmq_list), best_cl_height_diff :
            ffi_ref.best_cl_height_diff, best_cl_signature : rs_ffi_interfaces
            :: FFIConversion :: ffi_from_opt(ffi_ref.best_cl_signature),
        }
    } unsafe fn ffi_to(obj : CoinbaseTransaction) -> * mut
    CoinbaseTransactionFFI
    {
        rs_ffi_interfaces ::
        boxed(CoinbaseTransactionFFI
        {
            base : rs_ffi_interfaces :: FFIConversion :: ffi_to(obj.base),
            coinbase_transaction_version : obj.coinbase_transaction_version,
            height : obj.height, merkle_root_mn_list : rs_ffi_interfaces ::
            FFIConversion :: ffi_to(obj.merkle_root_mn_list),
            merkle_root_llmq_list : rs_ffi_interfaces :: FFIConversion ::
            ffi_to_opt(obj.merkle_root_llmq_list), best_cl_height_diff :
            obj.best_cl_height_diff, best_cl_signature : rs_ffi_interfaces ::
            FFIConversion :: ffi_to_opt(obj.best_cl_signature),
        })
    } unsafe fn destroy(ffi : * mut CoinbaseTransactionFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for CoinbaseTransactionFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < crate :: tx :: transaction ::
            TransactionFFI as rs_ffi_interfaces :: FFIConversion < crate :: tx
            :: transaction :: Transaction >> :: destroy(ffi_ref.base) ; {} ;
            {} ; < [u8 ; 32] as rs_ffi_interfaces :: FFIConversion < UInt256
            >> :: destroy(ffi_ref.merkle_root_mn_list) ; if!
            ffi_ref.merkle_root_llmq_list.is_null()
            {
                rs_ffi_interfaces :: unbox_any(ffi_ref.merkle_root_llmq_list)
                ;
            } ; {} ; if! ffi_ref.best_cl_signature.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.best_cl_signature) ; } ;
        }
    }
}
#[repr(C)] pub enum TransactionType
{
    Classic = 0, ProviderRegistration = 1, ProviderUpdateService = 2,
    ProviderUpdateRegistrar = 3, ProviderUpdateRevocation = 4, Coinbase = 5,
    QuorumCommitment = 6, SubscriptionRegistration = 8, SubscriptionTopUp = 9,
    SubscriptionResetKey = 10, SubscriptionCloseAccount = 11, Transition = 12,
    #[doc = " TODO: find actual value for this type"] CreditFunding = 255,
} #[doc = "FFI-representation of the"] #[doc = "TransactionType"] #[repr(C)]
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Hash, Ord)] pub enum
TransactionTypeFFI
{
    Classic = 0, ProviderRegistration = 1, ProviderUpdateService = 2,
    ProviderUpdateRegistrar = 3, ProviderUpdateRevocation = 4, Coinbase = 5,
    QuorumCommitment = 6, SubscriptionRegistration = 8, SubscriptionTopUp = 9,
    SubscriptionResetKey = 10, SubscriptionCloseAccount = 11, Transition = 12,
    CreditFunding = 255,
} impl rs_ffi_interfaces :: FFIConversion < TransactionType > for
TransactionTypeFFI
{
    unsafe fn ffi_from(ffi : * mut TransactionTypeFFI) -> TransactionType
    {
        let ffi_ref = & * ffi ; match ffi_ref
        {
            TransactionTypeFFI :: Classic => TransactionType :: Classic,
            TransactionTypeFFI :: ProviderRegistration => TransactionType ::
            ProviderRegistration, TransactionTypeFFI :: ProviderUpdateService
            => TransactionType :: ProviderUpdateService, TransactionTypeFFI ::
            ProviderUpdateRegistrar => TransactionType ::
            ProviderUpdateRegistrar, TransactionTypeFFI ::
            ProviderUpdateRevocation => TransactionType ::
            ProviderUpdateRevocation, TransactionTypeFFI :: Coinbase =>
            TransactionType :: Coinbase, TransactionTypeFFI ::
            QuorumCommitment => TransactionType :: QuorumCommitment,
            TransactionTypeFFI :: SubscriptionRegistration => TransactionType
            :: SubscriptionRegistration, TransactionTypeFFI ::
            SubscriptionTopUp => TransactionType :: SubscriptionTopUp,
            TransactionTypeFFI :: SubscriptionResetKey => TransactionType ::
            SubscriptionResetKey, TransactionTypeFFI ::
            SubscriptionCloseAccount => TransactionType ::
            SubscriptionCloseAccount, TransactionTypeFFI :: Transition =>
            TransactionType :: Transition, TransactionTypeFFI :: CreditFunding
            => TransactionType :: CreditFunding
        }
    } unsafe fn ffi_to(obj : TransactionType) -> * mut TransactionTypeFFI
    {
        rs_ffi_interfaces ::
        boxed(match obj
        {
            TransactionType :: Classic => TransactionTypeFFI :: Classic,
            TransactionType :: ProviderRegistration => TransactionTypeFFI ::
            ProviderRegistration, TransactionType :: ProviderUpdateService =>
            TransactionTypeFFI :: ProviderUpdateService, TransactionType ::
            ProviderUpdateRegistrar => TransactionTypeFFI ::
            ProviderUpdateRegistrar, TransactionType ::
            ProviderUpdateRevocation => TransactionTypeFFI ::
            ProviderUpdateRevocation, TransactionType :: Coinbase =>
            TransactionTypeFFI :: Coinbase, TransactionType ::
            QuorumCommitment => TransactionTypeFFI :: QuorumCommitment,
            TransactionType :: SubscriptionRegistration => TransactionTypeFFI
            :: SubscriptionRegistration, TransactionType :: SubscriptionTopUp
            => TransactionTypeFFI :: SubscriptionTopUp, TransactionType ::
            SubscriptionResetKey => TransactionTypeFFI ::
            SubscriptionResetKey, TransactionType :: SubscriptionCloseAccount
            => TransactionTypeFFI :: SubscriptionCloseAccount, TransactionType
            :: Transition => TransactionTypeFFI :: Transition, TransactionType
            :: CreditFunding => TransactionTypeFFI :: CreditFunding
        })
    } unsafe fn destroy(ffi : * mut TransactionTypeFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TransactionTypeFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            match self
            {
                TransactionTypeFFI :: Classic => {}, TransactionTypeFFI ::
                ProviderRegistration => {}, TransactionTypeFFI ::
                ProviderUpdateService => {}, TransactionTypeFFI ::
                ProviderUpdateRegistrar => {}, TransactionTypeFFI ::
                ProviderUpdateRevocation => {}, TransactionTypeFFI :: Coinbase
                => {}, TransactionTypeFFI :: QuorumCommitment => {},
                TransactionTypeFFI :: SubscriptionRegistration => {},
                TransactionTypeFFI :: SubscriptionTopUp => {},
                TransactionTypeFFI :: SubscriptionResetKey => {},
                TransactionTypeFFI :: SubscriptionCloseAccount => {},
                TransactionTypeFFI :: Transition => {}, TransactionTypeFFI ::
                CreditFunding => {},
            }
        }
    }
}
pub struct TransactionInput
{
    pub input_hash : UInt256, pub index : u32, pub script : Option < Vec < u8
    > >, pub signature : Option < Vec < u8 > >, pub sequence : u32,
} #[doc = "FFI-representation of the"] #[doc = "TransactionInput"] #[repr(C)]
#[derive(Clone, Debug)] pub struct TransactionInputFFI
{
    pub input_hash : * mut [u8 ; 32], pub index : u32, pub script : * mut
    rs_ffi_interfaces :: VecFFI < u8 >, pub signature : * mut
    rs_ffi_interfaces :: VecFFI < u8 >, pub sequence : u32,
} impl rs_ffi_interfaces :: FFIConversion < TransactionInput > for
TransactionInputFFI
{
    unsafe fn ffi_from(ffi : * mut TransactionInputFFI) -> TransactionInput
    {
        let ffi_ref = & * ffi ; TransactionInput
        {
            input_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_from(ffi_ref.input_hash), index : ffi_ref.index, script :
            (!
            ffi_ref.script.is_null()).then_some({
                let vec = & * ffi_ref.script ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }), signature :
            (!
            ffi_ref.signature.is_null()).then_some({
                let vec = & * ffi_ref.signature ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }), sequence : ffi_ref.sequence,
        }
    } unsafe fn ffi_to(obj : TransactionInput) -> * mut TransactionInputFFI
    {
        rs_ffi_interfaces ::
        boxed(TransactionInputFFI
        {
            input_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.input_hash), index : obj.index, script : match
            obj.script
            {
                Some(vec) => rs_ffi_interfaces ::
                boxed(rs_ffi_interfaces :: VecFFI :: new(vec.clone())), None
                => std :: ptr :: null_mut()
            }, signature : match obj.signature
            {
                Some(vec) => rs_ffi_interfaces ::
                boxed(rs_ffi_interfaces :: VecFFI :: new(vec.clone())), None
                => std :: ptr :: null_mut()
            }, sequence : obj.sequence,
        })
    } unsafe fn destroy(ffi : * mut TransactionInputFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TransactionInputFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; < [u8 ; 32] as rs_ffi_interfaces ::
            FFIConversion < UInt256 >> :: destroy(ffi_ref.input_hash) ; {} ;
            if! ffi_ref.script.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.script) ; ; } ; if!
            ffi_ref.signature.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.signature) ; ; } ; {} ;
        }
    }
}
pub struct TransactionOutput
{
    pub amount : u64, pub script : Option < Vec < u8 > >, pub address : Option
    < Vec < u8 > >,
} #[doc = "FFI-representation of the"] #[doc = "TransactionOutput"] #[repr(C)]
#[derive(Clone, Debug)] pub struct TransactionOutputFFI
{
    pub amount : u64, pub script : * mut rs_ffi_interfaces :: VecFFI < u8 >,
    pub address : * mut rs_ffi_interfaces :: VecFFI < u8 >,
} impl rs_ffi_interfaces :: FFIConversion < TransactionOutput > for
TransactionOutputFFI
{
    unsafe fn ffi_from(ffi : * mut TransactionOutputFFI) -> TransactionOutput
    {
        let ffi_ref = & * ffi ; TransactionOutput
        {
            amount : ffi_ref.amount, script :
            (!
            ffi_ref.script.is_null()).then_some({
                let vec = & * ffi_ref.script ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }), address :
            (!
            ffi_ref.address.is_null()).then_some({
                let vec = & * ffi_ref.address ; std :: slice ::
                from_raw_parts(vec.values as * const u8, vec.count).to_vec()
            }),
        }
    } unsafe fn ffi_to(obj : TransactionOutput) -> * mut TransactionOutputFFI
    {
        rs_ffi_interfaces ::
        boxed(TransactionOutputFFI
        {
            amount : obj.amount, script : match obj.script
            {
                Some(vec) => rs_ffi_interfaces ::
                boxed(rs_ffi_interfaces :: VecFFI :: new(vec.clone())), None
                => std :: ptr :: null_mut()
            }, address : match obj.address
            {
                Some(vec) => rs_ffi_interfaces ::
                boxed(rs_ffi_interfaces :: VecFFI :: new(vec.clone())), None
                => std :: ptr :: null_mut()
            },
        })
    } unsafe fn destroy(ffi : * mut TransactionOutputFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TransactionOutputFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; {} ; if! ffi_ref.script.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.script) ; ; } ; if!
            ffi_ref.address.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.address) ; ; } ;
        }
    }
}
pub struct Transaction
{
    pub inputs : Vec < TransactionInput >, pub outputs : Vec <
    TransactionOutput >, pub lock_time : u32, pub version : u16, pub tx_hash :
    Option < UInt256 >, pub tx_type : TransactionType, pub payload_offset :
    usize, pub block_height : u32,
} #[doc = "FFI-representation of the"] #[doc = "Transaction"] #[repr(C)]
#[derive(Clone, Debug)] pub struct TransactionFFI
{
    pub inputs : * mut rs_ffi_interfaces :: VecFFI < * mut TransactionInputFFI
    >, pub outputs : * mut rs_ffi_interfaces :: VecFFI < * mut
    TransactionOutputFFI >, pub lock_time : u32, pub version : u16, pub
    tx_hash : * mut [u8 ; 32], pub tx_type : * mut TransactionTypeFFI, pub
    payload_offset : usize, pub block_height : u32,
} impl rs_ffi_interfaces :: FFIConversion < Transaction > for TransactionFFI
{
    unsafe fn ffi_from(ffi : * mut TransactionFFI) -> Transaction
    {
        let ffi_ref = & * ffi ; Transaction
        {
            inputs :
            {
                let vec = & * ffi_ref.inputs ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }, outputs :
            {
                let vec = & * ffi_ref.outputs ;
                (0 ..
                vec.count).map(| i | rs_ffi_interfaces :: FFIConversion ::
                ffi_from(* vec.values.add(i))).collect()
            }, lock_time : ffi_ref.lock_time, version : ffi_ref.version,
            tx_hash : rs_ffi_interfaces :: FFIConversion ::
            ffi_from_opt(ffi_ref.tx_hash), tx_type : rs_ffi_interfaces ::
            FFIConversion :: ffi_from(ffi_ref.tx_type), payload_offset :
            ffi_ref.payload_offset, block_height : ffi_ref.block_height,
        }
    } unsafe fn ffi_to(obj : Transaction) -> * mut TransactionFFI
    {
        rs_ffi_interfaces ::
        boxed(TransactionFFI
        {
            inputs : rs_ffi_interfaces ::
            boxed({
                let vec = obj.inputs ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }), outputs : rs_ffi_interfaces ::
            boxed({
                let vec = obj.outputs ; rs_ffi_interfaces :: VecFFI
                {
                    count : vec.len(), values : rs_ffi_interfaces ::
                    boxed_vec(vec.into_iter().map(| o | rs_ffi_interfaces ::
                    FFIConversion :: ffi_to(o)).collect())
                }
            }), lock_time : obj.lock_time, version : obj.version, tx_hash :
            rs_ffi_interfaces :: FFIConversion :: ffi_to_opt(obj.tx_hash),
            tx_type : rs_ffi_interfaces :: FFIConversion ::
            ffi_to(obj.tx_type), payload_offset : obj.payload_offset,
            block_height : obj.block_height,
        })
    } unsafe fn destroy(ffi : * mut TransactionFFI)
    { rs_ffi_interfaces :: unbox_any(ffi) ; }
} impl Drop for TransactionFFI
{
    fn drop(& mut self)
    {
        unsafe
        {
            let ffi_ref = self ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.inputs) ; ; rs_ffi_interfaces ::
            unbox_any(ffi_ref.outputs) ; ; {} ; {} ; if!
            ffi_ref.tx_hash.is_null()
            { rs_ffi_interfaces :: unbox_any(ffi_ref.tx_hash) ; } ; <
            TransactionTypeFFI as rs_ffi_interfaces :: FFIConversion <
            TransactionType >> :: destroy(ffi_ref.tx_type) ; {} ; {} ;
        }
    }
}
// #![feature(prelude_import)]
// #![allow(dead_code)]
// #![allow(unused_variables)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
pub extern crate dash_spv_masternode_processor;
pub extern crate merk;
