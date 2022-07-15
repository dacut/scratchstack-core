use {
    super::MatchesActor,
    crate::{
        actor,
        utils::{validate_account_id, validate_name, validate_partition, validate_path},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::Hash,
    },
};

/// Details about an role principal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct User {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// The path of the role.
    path: String,

    /// Name of the user, case-insensitive.
    user_name: String,
}

impl User {
    /// Create a [User] object.
    ///
    /// # Arguments
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `path`: The IAM path the group is under. This must meet the following requirements or a
    ///     [PrincipalError::InvalidPath] error will be returned:
    ///     *   The path must contain between 1 and 512 characters.
    ///     *   The path must start and end with `/`.
    ///     *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
    ///         erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
    /// * `user_name`: The name of the user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidUserName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session`: Session details about the user.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [UserDetails] object is returned. Otherwise, a [PrincipalError] error
    /// is returned.
    pub fn new(partition: &str, account_id: &str, path: &str, user_name: &str) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_path(path)?;
        validate_name(user_name, 64, PrincipalError::InvalidUserName)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            path: path.into(),
            user_name: user_name.into(),
        })
    }

    pub fn partition(&self) -> &str {
        &self.partition
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn user_name(&self) -> &str {
        &self.user_name
    }
}

impl ToArn for User {
    fn to_arn(&self) -> String {
        format!("arn:{}:iam::{}:user{}{}", self.partition, self.account_id, self.path, self.user_name)
    }
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

impl MatchesActor<actor::Principal> for User {
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

impl MatchesActor<actor::AssumedRole> for User {
    fn matches(&self, _: &actor::AssumedRole) -> bool {
        false
    }
}

impl MatchesActor<actor::FederatedUser> for User {
    fn matches(&self, _: &actor::FederatedUser) -> bool {
        false
    }
}

impl MatchesActor<actor::RootUser> for User {
    fn matches(&self, _: &actor::RootUser) -> bool {
        false
    }
}

impl MatchesActor<actor::Service> for User {
    fn matches(&self, _: &actor::Service) -> bool {
        false
    }
}

impl MatchesActor<actor::User> for User {
    fn matches(&self, other: &actor::User) -> bool {
        self.partition == other.partition()
            && self.account_id == other.account_id()
            && self.path == other.path()
            && self.user_name == other.user_name()
    }
}
