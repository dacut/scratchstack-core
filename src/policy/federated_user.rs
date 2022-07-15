use {
    super::MatchesActor,
    crate::{
        actor,
        utils::{validate_account_id, validate_name, validate_partition},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::Hash,
    },
};

/// Details about an role principal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FederatedUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Name of the user
    user_name: String,
}

impl FederatedUser {
    /// Create an [Role] object.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidFederatedUserName] error will be returned:
    ///     *   The name must contain between 2 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [Role] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new(partition: &str, account_id: &str, user_name: &str) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_name(user_name, 32, PrincipalError::InvalidFederatedUserName)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            user_name: user_name.into(),
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

    #[inline]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

impl ToArn for FederatedUser {
    fn to_arn(&self) -> String {
        format!("arn:{}:iam::{}:federated-use/{}", self.partition, self.account_id, self.user_name)
    }
}

impl Display for FederatedUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

impl MatchesActor<actor::Principal> for FederatedUser {
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

impl MatchesActor<actor::AssumedRole> for FederatedUser {
    fn matches(&self, _: &actor::AssumedRole) -> bool {
        false
    }
}

impl MatchesActor<actor::FederatedUser> for FederatedUser {
    fn matches(&self, other: &actor::FederatedUser) -> bool {
        self.partition == other.partition()
            && self.account_id == other.account_id()
            && self.user_name == other.user_name()
    }
}

impl MatchesActor<actor::RootUser> for FederatedUser {
    fn matches(&self, _: &actor::RootUser) -> bool {
        false
    }
}

impl MatchesActor<actor::Service> for FederatedUser {
    fn matches(&self, _: &actor::Service) -> bool {
        false
    }
}

impl MatchesActor<actor::User> for FederatedUser {
    fn matches(&self, _: &actor::User) -> bool {
        false
    }
}
