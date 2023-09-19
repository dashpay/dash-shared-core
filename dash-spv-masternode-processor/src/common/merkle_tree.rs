use byte::BytesExt;
use crate::consensus::Encodable;
use crate::crypto::byte_util::BytesDecodable;
use crate::crypto::{UInt256, VarBytes};
use crate::crypto::var_array::VarArray;

#[inline]
fn ceil_log2(mut x: i32) -> i32 {
    let mut r = if x & (x - 1) != 0 { 1 } else { 0 };
    loop {
        x >>= 1;
        if x == 0 {
            break;
        }
        r += 1;
    }
    r
}

#[derive(Clone, Debug)]
pub struct MerkleTree<'a> {
    pub tree_element_count: u32,
    pub hashes: Vec<UInt256>,
    pub flags: &'a [u8],
}

impl<'a> MerkleTree<'a> {

    pub fn has_root(&self, desired_merkle_root: UInt256) -> bool {
        if self.tree_element_count == 0 {
            return true;
        }
        if let Some(root) = self.merkle_root() {
            if root == desired_merkle_root {
                return true;
            }
        }
        false
    }

    pub fn merkle_root(&self) -> Option<UInt256> {
        let hash_idx = &mut 0;
        let flag_idx = &mut 0;
        self.walk_hash_idx(
            hash_idx,
            flag_idx,
            0,
            |hash, _flag| hash,
            |left, right| {
                let mut buffer: Vec<u8> = Vec::with_capacity(64);
                left.enc(&mut buffer);
                right.unwrap_or(left).enc(&mut buffer);
                Some(UInt256::sha256d(buffer))
            },
        )
    }

    pub fn walk_hash_idx<
        BL: Fn(UInt256, Option<UInt256>) -> Option<UInt256> + Copy,
        LL: Fn(Option<UInt256>, bool) -> Option<UInt256> + Copy,
    >(
        &self,
        hash_idx: &mut usize,
        flag_idx: &mut usize,
        depth: i32,
        leaf: LL,
        branch: BL,
    ) -> Option<UInt256> {
        let flags_length = self.flags.len();
        let hashes_length = self.hashes.len();
        if *flag_idx / 8 >= flags_length || *hash_idx >= hashes_length {
            return leaf(None, false);
        }
        let flag = self.flags[*flag_idx / 8] & (1 << (*flag_idx % 8)) != 0;
        *flag_idx += 1;
        if !flag || depth == ceil_log2(self.tree_element_count as i32) {
            let hash = self.hashes.get(*hash_idx).copied();
            *hash_idx += 1;
            return leaf(hash, flag);
        }
        let left = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        let right = self.walk_hash_idx(hash_idx, flag_idx, depth + 1, leaf, branch);
        branch(left.unwrap(), right)
    }
}

impl<'a> BytesDecodable<'a, MerkleTree<'a>> for MerkleTree<'a> {
    fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> byte::Result<Self> {
        bytes.read_with(offset, byte::LE)
    }
}

impl<'a> byte::TryRead<'a, byte::ctx::Endian> for MerkleTree<'a> {
    fn try_read(bytes: &'a [u8], _endian: byte::ctx::Endian) -> byte::Result<(Self, usize)> {
        let offset = &mut 0;
        let total_transactions = u32::from_bytes(bytes, offset).unwrap();
        let merkle_hashes = VarArray::<UInt256>::from_bytes(bytes, offset).unwrap();
        let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset).unwrap();
        let tree = MerkleTree {
            tree_element_count: total_transactions,
            hashes: merkle_hashes.1,
            flags: merkle_flags_var_bytes.1
        };
        Ok((tree, *offset))
    }
}
