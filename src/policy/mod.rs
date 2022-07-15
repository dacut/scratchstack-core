mod account;
mod assumed_role;
mod federated_user;
mod role;
mod service;
mod user;

pub use {
    account::Account, assumed_role::AssumedRole, federated_user::FederatedUser, role::Role, service::Service,
    user::User,
};

use crate::{actor, TryToArn};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Principal {
    Account(Account),
    AssumedRole(AssumedRole),
    FederatedUser(FederatedUser),
    Role(Role),
    Service(Service),
    User(User),
}

impl From<Account> for Principal {
    fn from(account: Account) -> Self {
        Self::Account(account)
    }
}

impl From<AssumedRole> for Principal {
    fn from(assumed_role: AssumedRole) -> Self {
        Self::AssumedRole(assumed_role)
    }
}

impl From<FederatedUser> for Principal {
    fn from(federated_user: FederatedUser) -> Self {
        Self::FederatedUser(federated_user)
    }
}

impl From<Role> for Principal {
    fn from(role: Role) -> Self {
        Self::Role(role)
    }
}

impl From<Service> for Principal {
    fn from(service: Service) -> Self {
        Self::Service(service)
    }
}

impl TryToArn for Principal {
    fn try_to_arn(&self) -> Option<String> {
        match self {
            Self::Account(account) => account.try_to_arn(),
            Self::AssumedRole(assumed_role) => assumed_role.try_to_arn(),
            Self::FederatedUser(federated_user) => federated_user.try_to_arn(),
            Self::Role(role) => role.try_to_arn(),
            Self::Service(_) => None,
            Self::User(user) => user.try_to_arn(),
        }
    }
}

pub trait MatchesActor<A> {
    fn matches(&self, actor: &A) -> bool;
}

impl MatchesActor<actor::Principal> for Principal {
    fn matches(&self, other: &actor::Principal) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}

impl MatchesActor<actor::AssumedRole> for Principal {
    fn matches(&self, other: &actor::AssumedRole) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}

impl MatchesActor<actor::FederatedUser> for Principal {
    fn matches(&self, other: &actor::FederatedUser) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}

impl MatchesActor<actor::RootUser> for Principal {
    fn matches(&self, other: &actor::RootUser) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}

impl MatchesActor<actor::Service> for Principal {
    fn matches(&self, other: &actor::Service) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}

impl MatchesActor<actor::User> for Principal {
    fn matches(&self, other: &actor::User) -> bool {
        match self {
            Self::Account(account) => account.matches(other),
            Self::AssumedRole(role) => role.matches(other),
            Self::FederatedUser(user) => user.matches(other),
            Self::Role(role) => role.matches(other),
            Self::Service(service) => service.matches(other),
            Self::User(user) => user.matches(other),
        }
    }
}
