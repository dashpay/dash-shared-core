use bitflags::bitflags;

bitflags! {
    #[derive(Copy, Clone, PartialEq, Debug)]
    pub struct RegistrationStep: u32 {
        const None = 0;
        const FundingTransactionCreation = 1;
        const FundingTransactionAccepted = 2;
        const LocalInWalletPersistence = 4;
        const ProofAvailable = 8;
        const L1Steps = Self::FundingTransactionCreation.bits() | Self::FundingTransactionAccepted.bits() | Self::LocalInWalletPersistence.bits() | Self::ProofAvailable.bits();
        const Identity = 16;
        const RegistrationSteps = Self::L1Steps.bits() | Self::Identity.bits();
        const Username = 32;
        const RegistrationStepsWithUsername = Self::RegistrationSteps.bits() | Self::Username.bits();
        const InvitationSteps = Self::LocalInWalletPersistence.bits() | Self::Identity.bits() | Self::Username.bits();
        const Profile = 64;
        const RegistrationStepsWithUsernameAndDashpayProfile = Self::RegistrationStepsWithUsername.bits() | Self::Profile.bits();
        const All = Self::RegistrationStepsWithUsernameAndDashpayProfile.bits();
        const Cancelled = 1 << 30;
    }
}
