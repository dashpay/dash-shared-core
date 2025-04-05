use std::cmp;
use std::cmp::Ordering;
use std::hash::Hash;
use super::IIndexPath;

#[derive(Clone, Debug, Default, Eq, Hash)]
pub struct UInt256IndexPath {
    pub indexes: Vec<[u8; 32]>,
    pub hardened_indexes: Vec<bool>,
    // hash: u64,
}

impl IIndexPath for UInt256IndexPath {
    type Item = [u8; 32];
    fn new(indexes: Vec<Self::Item>) -> Self {
        Self { indexes, ..Default::default() }
    }

    fn new_hardened(indexes: Vec<Self::Item>, hardened: Vec<bool>) -> Self {
        Self { indexes, hardened_indexes: hardened }
    }

    fn indexes(&self) -> &Vec<Self::Item> {
        &self.indexes
    }
    fn hardened_indexes(&self) -> &Vec<bool> {
        &self.hardened_indexes
    }
}

impl Ord for UInt256IndexPath {
    fn cmp(&self, other: &Self) -> Ordering {
        let length1 = self.length();
        let length2 = other.length();
        for position in 0..cmp::min(length1, length2) {
            let result = self.index_at_position(position).cmp(&other.index_at_position(position));
            if result != Ordering::Equal {
                return result;
            }
        }
        length1.cmp(&length2)
    }
}


impl PartialOrd for UInt256IndexPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}


impl PartialEq for UInt256IndexPath {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

// Preventing hash collisions:
// https://www.mikeash.com/pyblog/friday-qa-2010-06-18-implementing-equality-and-hashing.html
// #define DSUINT_BIT (CHAR_BIT * sizeof(NSUInteger))
// #define DSUINTROTATE(val, howmuch) ((((NSUInteger)val) << howmuch) | (((NSUInteger)val) >> (DSUINT_BIT - howmuch)))
//
// const BIT: u8 = 32;
// fn uint_rotate(val: u64, howmuch: u8) -> u64 {
//     val << howmuch | val >> (64 - howmuch)
// }
//
// impl Hash for UInt256IndexPath  {
//     fn hash<H: Hasher>(&self, state: &mut H) {
//         // if self.hash == 0 {
//             let l = self.length();
//             let mut hash = l as u64;
//             self.indexes()
//                 .iter()
//                 .for_each(|index|
//                     hash += uint_rotate(index.u64_le() ^ index.u64_2_le(), BIT) ^ uint_rotate(index.u64_3_le() ^ index.u64_4_le(), BIT)
//                 );
//             // self.hash = hash;
//         // }
//         state.write_u64(hash);
//         //state.finish();
//     }
// }
