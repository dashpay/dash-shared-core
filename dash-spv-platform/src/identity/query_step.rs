use bitflags::bitflags;
use crate::identity::registration_step::RegistrationStep;
// #[repr(u32)]
// #[derive(Copy, Clone, PartialEq, Debug, Eq)]
// #[ferment_macro::export]
// pub enum QueryStep {
//     None                        = 0,
//     Identity                    = 1 << 4, // 16
//     Username                    = 1 << 5, // 32
//     Profile                     = 1 << 6, // 64
//     IncomingContactRequests     = 1 << 7, // 128
//     OutgoingContactRequests     = 1 << 8, // 256
//
//     ContactRequests             = (1 << 7) | (1 << 8),
//     AllForForeignIdentity       = (1 << 4) | (1 << 5) | (1 << 6),
//     AllForLocalIdentity         = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8),
//
//     NoIdentity                  = 1 << 28,
//     BadQuery                    = 1 << 29,
//     Cancelled                   = 1 << 30,
// }

bitflags! {
    #[derive(Copy, Clone, PartialEq, Debug)]
    pub struct QueryStep: u32 {
        const None = RegistrationStep::None.bits();
        const Identity = RegistrationStep::Identity.bits();
        const Username = RegistrationStep::Username.bits();
        const Profile = RegistrationStep::Profile.bits();
        const IncomingContactRequests = 1 << 7;
        const OutgoingContactRequests = 1 << 8;
        const ContactRequests = Self::IncomingContactRequests.bits() | Self::OutgoingContactRequests.bits();
        const AllForForeignIdentity = Self::Identity.bits() | Self::Username.bits() | Self::Profile.bits();
        const NoIdentity = 1 << 28;
        const BadQuery = 1 << 29;
        const Cancelled = 1 << 30;
    }
}
