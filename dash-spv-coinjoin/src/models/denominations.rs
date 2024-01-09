use dash_spv_masternode_processor::chain::params::DUFFS;

pub enum Denomination {
    Ten,
    One,
    Tenth,
    Hundredth,
    Thousandth,
    Smallest,
}

impl Denomination {
    fn value(&self) -> u64 {
        match self {
            Denomination::Ten => DUFFS * 10 + 10_000,
            Denomination::One => DUFFS + 1_000,
            Denomination::Tenth => DUFFS / 10 + 100,
            Denomination::Hundredth => DUFFS / 100 + 10,
            Denomination::Thousandth => DUFFS / 1_000 + 1,
            Denomination::Smallest => Denomination::Thousandth.value(),
        }
    }

    pub fn all_values() -> Vec<u64> {
        vec![
            Denomination::Ten.value(),
            Denomination::One.value(),
            Denomination::Tenth.value(),
            Denomination::Hundredth.value(),
            Denomination::Thousandth.value(),
            Denomination::Smallest.value(),
        ]
    }
}
