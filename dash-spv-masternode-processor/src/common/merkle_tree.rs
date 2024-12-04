use std::io::Read;
use hashes::{sha256d, Hash};
use dash_spv_crypto::consensus::{Decodable, Encodable};
use dash_spv_crypto::consensus::encode::Error;

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
pub struct MerkleTree {
    pub tree_element_count: u32,
    pub hashes: Vec<[u8; 32]>,
    pub flags: Vec<u8>,
}

impl MerkleTree {

    pub fn has_root(&self, desired_merkle_root: [u8; 32]) -> bool {
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

    pub fn merkle_root(&self) -> Option<[u8; 32]> {
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
                Some(sha256d::Hash::hash(&buffer).into_inner())
            },
        )
    }

    pub fn walk_hash_idx<
        BL: Fn([u8; 32], Option<[u8; 32]>) -> Option<[u8; 32]> + Copy,
        LL: Fn(Option<[u8; 32]>, bool) -> Option<[u8; 32]> + Copy,
    >(
        &self,
        hash_idx: &mut usize,
        flag_idx: &mut usize,
        depth: i32,
        leaf: LL,
        branch: BL,
    ) -> Option<[u8; 32]> {
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
        branch(left?, right)
    }
}

// impl<'a> BytesDecodable<'a, MerkleTree> for MerkleTree {
//     fn from_bytes(bytes: &'a [u8], offset: &mut usize) -> byte::Result<Self> {
//         bytes.read_with(offset, byte::LE)
//     }
// }

// impl<'a> byte::TryRead<'a, byte::ctx::Endian> for MerkleTree {
//     fn try_read(bytes: &'a [u8], _endian: byte::ctx::Endian) -> byte::Result<(Self, usize)> {
//         let offset = &mut 0;
//         let total_transactions = u32::from_bytes(bytes, offset)?;
//         let merkle_hashes = VarArray::<[u8; 32]>::from_bytes(bytes, offset)?;
//         let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset)?;
//         let tree = MerkleTree {
//             tree_element_count: total_transactions,
//             hashes: merkle_hashes.1,
//             flags: merkle_flags_var_bytes.1.to_vec()
//         };
//         Ok((tree, *offset))
//     }
// }
impl<'a> Decodable for MerkleTree {
    #[inline]
    fn consensus_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        // let data = <[u8; 48]>::consensus_decode(&mut d)?;
        let total_transactions = u32::consensus_decode(&mut d)?;
        let merkle_hashes = <Vec<[u8; 32]>>::consensus_decode(&mut d)?;
        let merkle_flags = <Vec<u8>>::consensus_decode(&mut d)?;
        // let merkle_hashes = VarArray::<[u8; 32]>::from_bytes(bytes, offset)?;
        // let merkle_flags_var_bytes = VarBytes::from_bytes(bytes, offset)?;
        let tree = MerkleTree {
            tree_element_count: total_transactions,
            hashes: merkle_hashes,
            flags: merkle_flags
        };

        Ok(tree)
    }
}

