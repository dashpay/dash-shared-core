use std::collections::HashSet;
use std::hash::Hash;
use byte::BytesExt;

pub trait Data {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool;
    fn true_bits_count(&self) -> u64;
}

impl Data for [u8] {

    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        let offset = &mut ((index / 8) as usize);
        let bit_position = index % 8;
        match self.read_with::<u8>(offset, byte::LE) {
            Ok(bits) => (bits >> bit_position) & 1 != 0,
            _ => false
        }
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        for mut i in 0..self.len() {
            let mut bits: u8 = self.read_with(&mut i, byte::LE).unwrap();
            for _j in 0..8 {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            }
        }
        count
    }
}

impl Data for Vec<u8> {
    fn bit_is_true_at_le_index(&self, index: u32) -> bool {
        (self[(index / 8) as usize] >> (index % 8)) & 1 != 0
    }

    fn true_bits_count(&self) -> u64 {
        let mut count = 0;
        self.iter().for_each(|bits| {
            let mut bits = bits.clone();
            (0..8).for_each(|_| {
                if bits & 1 != 0 {
                    count += 1;
                }
                bits >>= 1;
            });
        });
        count
    }
}


/// Extracts the common values in `a` and `b` into a new set.
#[inline]
pub fn inplace_intersection<T>(a: &mut HashSet<T>, b: &HashSet<T>) -> HashSet<T> where T: Hash + Eq + Clone {
    let intersection: HashSet<T> = a.iter().filter(|v| b.contains(v)).cloned().collect();
    a.retain(|v| !b.contains(v));
    intersection
}

pub fn extract_new_and_unique<T>(a: Vec<T>, b: Vec<T>) -> (Vec<T>, Vec<T>) where T: Clone + Eq + Hash {
    let a_set: HashSet<_> = a.iter().cloned().collect(); // convert A to a set for fast lookup
    let (c, d): (Vec<_>, Vec<_>) = b.into_iter()
        .filter(|x| !a_set.contains(x)) // keep elements that are not in A
        .partition(|x| a_set.contains(x)); // partition elements based on whether they are in A

    (c, d)
}

pub fn extend_unique<T>(a: &mut Vec<T>, b: Vec<T>) where T: PartialEq + Clone {
    a.extend(b.iter().filter(|x| !a.contains(x)).cloned().collect::<Vec<_>>());
}
