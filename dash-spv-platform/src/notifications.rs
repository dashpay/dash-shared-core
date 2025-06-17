use dash_spv_crypto::network::ChainType;
use crate::identity::invitation::InvitationModel;
use crate::identity::model::IdentityModel;

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct IdentityDidUpdate {
    pub chain_type: ChainType,
    pub identity: IdentityModel,
    pub events: Vec<&'static str>
}
impl IdentityDidUpdate {
    pub fn new(chain_type: ChainType, identity: IdentityModel, events: Vec<&'static str>) -> IdentityDidUpdate {
        Self { chain_type, identity, events }
    }
}
#[ferment_macro::export]
impl IdentityDidUpdate {
    pub fn chain_type(&self) -> ChainType {
        self.chain_type.clone()
    }
    pub fn identity(&self) -> IdentityModel {
        self.identity.clone()
    }
    pub fn events(&self) -> Vec<&'static str> {
        self.events.clone()
    }
}

#[derive(Clone, Debug)]
#[ferment_macro::opaque]
pub struct InvitationDidUpdate {
    pub chain_type: ChainType,
    pub invitation: InvitationModel,
}

impl InvitationDidUpdate {
    pub fn new(chain_type: ChainType, invitation: InvitationModel) -> InvitationDidUpdate {
        Self { chain_type, invitation }
    }
}

#[ferment_macro::export]
impl InvitationDidUpdate {
    pub fn chain_type(&self) -> ChainType {
        self.chain_type.clone()
    }
    pub fn invitation(&self) -> InvitationModel {
        self.invitation.clone()
    }

}
