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

/// Details about an assumed role principal.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct AssumedRole {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Name of the role, case-insensitive.
    role_name: String,

    /// Session name for the assumed role.
    session_name: String,
}

impl AssumedRole {
    /// Create an [AssumedRole] object.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///     [PrincipalError::InvalidSessionName] error will be returned:
    ///     *   The session name must contain between 2 and 64 characters.
    ///     *   The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [AssumedRole] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new(partition: &str, account_id: &str, role_name: &str, session_name: &str) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_name(role_name, 64, PrincipalError::InvalidRoleName)?;
        validate_name(session_name, 64, PrincipalError::InvalidSessionName)?;

        if session_name.len() < 2 {
            Err(PrincipalError::InvalidSessionName(session_name.to_string()))
        } else {
            Ok(Self {
                partition: partition.into(),
                account_id: account_id.into(),
                role_name: role_name.into(),
                session_name: session_name.into(),
            })
        }
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
    pub fn role_name(&self) -> &str {
        &self.role_name
    }

    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
    }
}

impl ToArn for AssumedRole {
    fn to_arn(&self) -> String {
        format!("arn:{}:sts::{}:assumed-role/{}/{}", self.partition, self.account_id, self.role_name, self.session_name)
    }
}

impl Display for AssumedRole {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

impl MatchesActor<actor::Principal> for AssumedRole {
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

impl MatchesActor<actor::AssumedRole> for AssumedRole {
    fn matches(&self, other: &actor::AssumedRole) -> bool {
        self.partition == other.partition()
            && self.account_id == other.account_id()
            && self.role_name == other.role_name()
            && self.session_name == other.session_name()
    }
}

impl MatchesActor<actor::FederatedUser> for AssumedRole {
    fn matches(&self, _: &actor::FederatedUser) -> bool {
        false
    }
}

impl MatchesActor<actor::RootUser> for AssumedRole {
    fn matches(&self, _: &actor::RootUser) -> bool {
        false
    }
}

impl MatchesActor<actor::Service> for AssumedRole {
    fn matches(&self, _: &actor::Service) -> bool {
        false
    }
}

impl MatchesActor<actor::User> for AssumedRole {
    fn matches(&self, _: &actor::User) -> bool {
        false
    }
}
