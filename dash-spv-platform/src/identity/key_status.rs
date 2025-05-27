#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[ferment_macro::export]
pub enum IdentityKeyStatus {
    Unknown = 0,
    Registered = 1,
    Registering = 2,
    NotRegistered = 3,
    Revoked = 4,
}

impl From<u8> for IdentityKeyStatus {
    fn from(value: u8) -> Self {
        match value {
            0 => IdentityKeyStatus::Unknown,
            1 => IdentityKeyStatus::Registered,
            2 => IdentityKeyStatus::Registering,
            3 => IdentityKeyStatus::NotRegistered,
            4 => IdentityKeyStatus::Revoked,
            _ => panic!("Invalid value for IdentityKeyStatus {value}"),
        }
    }
}

impl From<&IdentityKeyStatus> for u8 {
    fn from(value: &IdentityKeyStatus) -> Self {
        match value {
            IdentityKeyStatus::Unknown => 0,
            IdentityKeyStatus::Registered => 1,
            IdentityKeyStatus::Registering => 2,
            IdentityKeyStatus::NotRegistered => 3,
            IdentityKeyStatus::Revoked => 4,
        }
    }
}

#[ferment_macro::export]
impl IdentityKeyStatus {
    pub fn to_index(&self) -> u8 {
        u8::from(self)
    }
    pub fn from_index(index: u8) -> IdentityKeyStatus {
        IdentityKeyStatus::from(index)
    }

    pub fn string(&self) -> String {
        match self {
            IdentityKeyStatus::Unknown => "Unknown",
            IdentityKeyStatus::Registered => "Registered",
            IdentityKeyStatus::Registering => "Registering",
            IdentityKeyStatus::NotRegistered => "Not Registered",
            IdentityKeyStatus::Revoked => "Revoked",
        }.to_string()
    }

    pub fn string_description(&self) -> String {
        format!("Status of Key or Username is {}", self.string())
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, IdentityKeyStatus::Unknown)
    }
    pub fn is_registered(&self) -> bool {
        matches!(self, IdentityKeyStatus::Registered)
    }
    pub fn is_registering(&self) -> bool {
        matches!(self, IdentityKeyStatus::Registering)
    }
    pub fn is_not_registered(&self) -> bool {
        matches!(self, IdentityKeyStatus::NotRegistered)
    }
    pub fn is_revoked(&self) -> bool {
        matches!(self, IdentityKeyStatus::Revoked)
    }
}