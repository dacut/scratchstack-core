use {
    super::MatchesActor,
    crate::{
        actor,
        utils::{validate_account_id, validate_partition},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::Hash,
    },
};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Account {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,
}

impl Account {
    pub fn new(partition: &str, account_id: &str) -> Result<Self, PrincipalError> {
        validate_partition(&partition)?;
        validate_account_id(&account_id)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
        })
    }

    #[inline]
    pub fn partition(&self) -> &str {
        &self.partition
    }

    #[inline]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }
}

impl ToArn for Account {
    fn to_arn(&self) -> String {
        format!("arn:{}:iam::{}:root", self.partition, self.account_id)
    }
}

impl Display for Account {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

impl MatchesActor<actor::Principal> for Account {
    fn matches(&self, other: &actor::Principal) -> bool {
        match other {
            actor::Principal::AssumedRole(role) => self.matches(role),
            actor::Principal::FederatedUser(user) => self.matches(user),
            actor::Principal::RootUser(user) => self.matches(user),
            actor::Principal::Service(service) => self.matches(service),
            actor::Principal::User(user) => self.matches(user),
        }
    }
}

impl MatchesActor<actor::AssumedRole> for Account {
    fn matches(&self, other: &actor::AssumedRole) -> bool {
        self.partition == other.partition() && self.account_id == other.account_id()
    }
}

impl MatchesActor<actor::FederatedUser> for Account {
    fn matches(&self, other: &actor::FederatedUser) -> bool {
        self.partition == other.partition() && self.account_id == other.account_id()
    }
}

impl MatchesActor<actor::RootUser> for Account {
    fn matches(&self, other: &actor::RootUser) -> bool {
        self.partition == other.partition() && self.account_id == other.account_id()
    }
}

impl MatchesActor<actor::Service> for Account {
    fn matches(&self, _: &actor::Service) -> bool {
        false
    }
}

impl MatchesActor<actor::User> for Account {
    fn matches(&self, other: &actor::User) -> bool {
        self.partition == other.partition() && self.account_id == other.account_id()
    }
}
