mod assumed_role;
mod federated_user;
mod root_user;
mod service;
mod user;

pub use {assumed_role::AssumedRole, federated_user::FederatedUser, root_user::RootUser, service::Service, user::User};

use {
    crate::TryToArn,
    std::fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// An active, identified AWS principal -- an actor who is making requests against a service.
///
/// In addition to the ARN, an IAM principal actor also has a unique id that changes whenever the principal is
/// recreated. This is in contrast to a PolicyPrincipal, which lacks this id.
pub enum Principal {
    /// Details for an assumed role.
    AssumedRole(AssumedRole),

    /// Details for a federated user.
    FederatedUser(FederatedUser),

    /// Details for the root user of an account.
    RootUser(RootUser),

    /// Details for a service.
    Service(Service),

    /// Details for an IAM user.
    User(User),
}

impl Principal {
    pub fn has_arn(&self) -> bool {
        match self {
            Principal::Service(_) => false,
            _ => true,
        }
    }
}

impl From<AssumedRole> for Principal {
    fn from(assumed_role: AssumedRole) -> Self {
        Principal::AssumedRole(assumed_role)
    }
}

impl From<FederatedUser> for Principal {
    fn from(federated_user: FederatedUser) -> Self {
        Principal::FederatedUser(federated_user)
    }
}

impl From<RootUser> for Principal {
    fn from(root_user: RootUser) -> Self {
        Principal::RootUser(root_user)
    }
}

impl From<Service> for Principal {
    fn from(service: Service) -> Self {
        Principal::Service(service)
    }
}

impl From<User> for Principal {
    fn from(user: User) -> Self {
        Principal::User(user)
    }
}

impl Clone for Principal {
    fn clone(&self) -> Self {
        match self {
            Principal::AssumedRole(assumed_role) => Principal::AssumedRole(assumed_role.clone()),
            Principal::FederatedUser(federated_user) => Principal::FederatedUser(federated_user.clone()),
            Principal::RootUser(root_user) => Principal::RootUser(root_user.clone()),
            Principal::Service(service) => Principal::Service(service.clone()),
            Principal::User(user) => Principal::User(user.clone()),
        }
    }
}

impl Debug for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Principal::AssumedRole(assumed_role) => f.debug_tuple("AssumedRole").field(assumed_role).finish(),
            Principal::FederatedUser(federated_user) => f.debug_tuple("FederatedUser").field(federated_user).finish(),
            Principal::RootUser(root_user) => f.debug_tuple("RootUser").field(root_user).finish(),
            Principal::Service(service) => f.debug_tuple("Service").field(service).finish(),
            Principal::User(user) => f.debug_tuple("User").field(user).finish(),
        }
    }
}

impl PartialEq for Principal {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Principal::AssumedRole(assumed_role), Principal::AssumedRole(other_assumed_role)) => {
                assumed_role == other_assumed_role
            }
            (Principal::FederatedUser(federated_user), Principal::FederatedUser(other_federated_user)) => {
                federated_user == other_federated_user
            }
            (Principal::RootUser(root_user), Principal::RootUser(other_root_user)) => root_user == other_root_user,
            (Principal::Service(service), Principal::Service(other_service)) => service == other_service,
            (Principal::User(user), Principal::User(other_user)) => user == other_user,
            _ => false,
        }
    }
}

impl Eq for Principal {}

impl Display for Principal {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::AssumedRole(ref inner) => Display::fmt(inner, f),
            Self::FederatedUser(ref inner) => Display::fmt(inner, f),
            Self::RootUser(ref inner) => Display::fmt(inner, f),
            Self::Service(ref inner) => Display::fmt(inner, f),
            Self::User(ref inner) => Display::fmt(inner, f),
        }
    }
}

impl TryToArn for Principal {
    fn try_to_arn(&self) -> Option<String> {
        match self {
            Self::AssumedRole(ref d) => d.try_to_arn(),
            Self::FederatedUser(ref d) => d.try_to_arn(),
            Self::RootUser(ref d) => d.try_to_arn(),
            Self::Service(_) => None,
            Self::User(ref d) => d.try_to_arn(),
        }
    }
}
