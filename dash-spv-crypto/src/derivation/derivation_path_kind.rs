#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[ferment_macro::export]
pub enum DerivationPathKind {
    ProviderVoting = 0,
    ProviderOwner = 1,
    ProviderOperator = 2,
    PlatformNode = 3,

    IdentityRegistrationFunding = 4,
    IdentityTopupFunding = 5,
    InvitationFunding = 6,
    IdentityBLS = 7,
    IdentityECDSA = 8
}

#[ferment_macro::export]
impl DerivationPathKind {
    pub fn from_index(index: u32) -> DerivationPathKind {
        match index {
            0 => DerivationPathKind::ProviderVoting,
            1 => DerivationPathKind::ProviderOwner,
            2 => DerivationPathKind::ProviderOperator,
            3 => DerivationPathKind::PlatformNode,
            4 => DerivationPathKind::IdentityRegistrationFunding,
            5 => DerivationPathKind::IdentityTopupFunding,
            6 => DerivationPathKind::InvitationFunding,
            7 => DerivationPathKind::IdentityBLS,
            8 => DerivationPathKind::IdentityECDSA,
            _ => panic!("Invalid DerivationPathKind {}", index)
        }
    }
    pub fn to_index(&self) -> u32 {
        match self {
            DerivationPathKind::ProviderVoting => 0,
            DerivationPathKind::ProviderOwner => 1,
            DerivationPathKind::ProviderOperator => 2,
            DerivationPathKind::PlatformNode => 3,
            DerivationPathKind::IdentityRegistrationFunding => 4,
            DerivationPathKind::IdentityTopupFunding => 5,
            DerivationPathKind::InvitationFunding => 6,
            DerivationPathKind::IdentityBLS => 7,
            DerivationPathKind::IdentityECDSA => 8
        }
    }
}