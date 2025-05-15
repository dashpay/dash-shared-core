// typedef NS_ENUM(NSUInteger, DSIdentityQueryStep)
// {
// DSIdentityQueryStep_None = DSIdentityRegistrationStep_None,         //0
// DSIdentityQueryStep_Identity = DSIdentityRegistrationStep_Identity, //16
// DSIdentityQueryStep_Username = DSIdentityRegistrationStep_Username, //32
// DSIdentityQueryStep_Profile = DSIdentityRegistrationStep_Profile,   //64
// DSIdentityQueryStep_IncomingContactRequests = 128,
// DSIdentityQueryStep_OutgoingContactRequests = 256,
// DSIdentityQueryStep_ContactRequests = DSIdentityQueryStep_IncomingContactRequests | DSIdentityQueryStep_OutgoingContactRequests,
// DSIdentityQueryStep_AllForForeignIdentity = DSIdentityQueryStep_Identity | DSIdentityQueryStep_Username | DSIdentityQueryStep_Profile,
// DSIdentityQueryStep_AllForLocalIdentity = DSIdentityQueryStep_Identity | DSIdentityQueryStep_Username | DSIdentityQueryStep_Profile | DSIdentityQueryStep_ContactRequests,
// DSIdentityQueryStep_NoIdentity = 1 << 28,
// DSIdentityQueryStep_BadQuery = 1 << 29,
// DSIdentityQueryStep_Cancelled = 1 << 30
// };
//

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Debug, Eq)]
#[ferment_macro::export]
pub enum QueryStep {
    None                        = 0,
    Identity                    = 1 << 4, // 16
    Username                    = 1 << 5, // 32
    Profile                     = 1 << 6, // 64
    IncomingContactRequests     = 1 << 7, // 128
    OutgoingContactRequests     = 1 << 8, // 256

    // Composite flags
    ContactRequests             = (1 << 7) | (1 << 8),
    AllForForeignIdentity       = (1 << 4) | (1 << 5) | (1 << 6),
    AllForLocalIdentity         = (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8),

    NoIdentity                  = 1 << 28,
    BadQuery                    = 1 << 29,
    Cancelled                   = 1 << 30,
}

