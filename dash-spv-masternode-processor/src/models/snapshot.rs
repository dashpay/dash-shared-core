use byte::ctx::{Bytes, Endian};
use byte::{BytesExt, TryRead, LE};
use hashes::hex::ToHex;
#[cfg(feature = "generate-dashj-tests")]
use serde::{Serialize, Serializer};
#[cfg(feature = "generate-dashj-tests")]
use serde::ser::SerializeStruct;
use crate::common::llmq_snapshot_skip_mode::LLMQSnapshotSkipMode;
use crate::consensus::encode::VarInt;
use crate::crypto::{byte_util::BytesDecodable, data_ops::Data};
use crate::impl_bytes_decodable;

#[derive(Clone)]
#[ferment_macro::export]
pub struct LLMQSnapshot {
    // The bitset of nodes already in quarters at the start of cycle at height n
    // (masternodeListSize + 7)/8
    pub member_list: Vec<u8>,
    // Skiplist at height n
    pub skip_list: Vec<i32>,
    //  Mode of the skip list
    pub skip_list_mode: LLMQSnapshotSkipMode,
}
impl Default for LLMQSnapshot {
    fn default() -> Self {
        Self {
            member_list: vec![],
            skip_list: vec![],
            skip_list_mode: LLMQSnapshotSkipMode::NoSkipping,
        }
    }
}

#[cfg(feature = "generate-dashj-tests")]
impl Serialize for LLMQSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        let mut state = serializer.serialize_struct("LLMQSnapshot", 3)?;
        let len = self.member_list.len() * 8 - 7;
        let members = (0..len).map(|i| self.member_is_true_at_index(i as u32)).collect::<Vec<_>>();
        state.serialize_field("member_list", &members)?;
        state.serialize_field("skip_list", &self.skip_list)?;
        state.serialize_field("skip_list_mode", &self.skip_list_mode)?;
        state.end()

    }
}

impl<'a> std::fmt::Debug for LLMQSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LLMQSnapshot")
            .field("member_list", &self.member_list.to_hex())
            .field("skip_list", &self.skip_list.iter())
            .field("skip_list_mode", &self.skip_list_mode)
            .finish()
    }
}
impl<'a> TryRead<'a, Endian> for LLMQSnapshot {
    fn try_read(bytes: &'a [u8], _ctx: Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let skip_list_mode = bytes.read_with::<LLMQSnapshotSkipMode>(offset, LE)?;
        let member_list_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let member_list: &[u8] =
            bytes.read_with(offset, Bytes::Len((member_list_length + 7) / 8))?;
        let skip_list_length = bytes.read_with::<VarInt>(offset, LE)?.0 as usize;
        let mut skip_list = Vec::with_capacity(skip_list_length);
        for _i in 0..skip_list_length {
            skip_list.push(bytes.read_with::<i32>(offset, LE)?);
        }
        let snapshot = Self {
            member_list: member_list.to_vec(),
            skip_list,
            skip_list_mode,
        };
        Ok((snapshot, *offset))
    }
}

impl LLMQSnapshot {

    pub fn new(member_list: Vec<u8>, skip_list: Vec<i32>, skip_list_mode: LLMQSnapshotSkipMode) -> Self {
        LLMQSnapshot {
            member_list,
            skip_list,
            skip_list_mode
        }
    }

    pub fn length(&self) -> usize {
        self.member_list.len() + 1 + 2 + self.skip_list.len() * 2
    }

    pub fn member_is_true_at_index(&self, i: u32) -> bool {
        self.member_list.as_slice().bit_is_true_at_le_index(i)
    }

}
impl_bytes_decodable!(LLMQSnapshot);

