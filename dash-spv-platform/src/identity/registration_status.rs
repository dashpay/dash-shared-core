#[ferment_macro::export]
#[derive(Clone, PartialEq, Eq)]
pub enum IdentityRegistrationStatus {
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3, //sent to DAPI, not yet confirmed
}

impl From<u8> for IdentityRegistrationStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => IdentityRegistrationStatus::Unknown,
            1 => IdentityRegistrationStatus::Registered,
            2 => IdentityRegistrationStatus::Registering,
            3 => IdentityRegistrationStatus::NotRegistered,
            _ => panic!("Invalid value for IdentityRegistrationStatus {value}"),
        }
    }
}

impl From<&IdentityRegistrationStatus> for u8 {
    fn from(value: &IdentityRegistrationStatus) -> Self {
        match value {
            IdentityRegistrationStatus::Unknown => 0,
            IdentityRegistrationStatus::Registered => 1,
            IdentityRegistrationStatus::Registering => 2,
            IdentityRegistrationStatus::NotRegistered => 3,
        }
    }
}

#[ferment_macro::export]
impl IdentityRegistrationStatus {
    pub fn to_index(&self) -> u8 {
        u8::from(self)
    }
    pub fn from_index(index: u8) -> IdentityRegistrationStatus {
        IdentityRegistrationStatus::from(index)
    }
    pub fn is_unknown(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Unknown)
    }
    pub fn is_registered(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Registered)
    }
    pub fn is_registering(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::Registering)
    }
    pub fn is_not_registered(&self) -> bool {
        matches!(self, IdentityRegistrationStatus::NotRegistered)
    }

    pub fn string(&self) -> String {
        match self {
            IdentityRegistrationStatus::Unknown => "Unknown",
            IdentityRegistrationStatus::Registered => "Registered",
            IdentityRegistrationStatus::Registering => "Registering",
            IdentityRegistrationStatus::NotRegistered => "Not Registered",
        }.to_string()
    }
}