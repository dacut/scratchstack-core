use {
    super::SessionData,
    crate::{
        utils::{validate_account_id, validate_name, validate_partition},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
    },
};

/// Details about a federated user.
pub struct FederatedUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Name of the principal, case-insensitive.
    user_name: String,

    /// Session data about the federated user.
    session: SessionData,
}

impl FederatedUser {
    /// Create a [FederatedUser] object.
    ///
    /// # Arguments:
    ///
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `user_name`: The name of the federated user. This must meet the following requirements or a
    ///     [PrincipalError::InvalidFederatedUserName] error will be returned:
    ///     *   The name must contain between 2 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session`: The session applied to the federated user.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, a [FederatedUserDetails] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new(
        partition: &str,
        account_id: &str,
        user_name: &str,
        session: SessionData,
    ) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_name(user_name, 32, PrincipalError::InvalidFederatedUserName)?;

        if user_name.len() < 2 {
            Err(PrincipalError::InvalidFederatedUserName(user_name.into()))
        } else {
            Ok(Self {
                partition: partition.into(),
                account_id: account_id.into(),
                user_name: user_name.into(),
                session: session,
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
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    #[inline]
    pub fn session(&self) -> &SessionData {
        &self.session
    }
}

impl Clone for FederatedUser {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            account_id: self.account_id.clone(),
            user_name: self.user_name.clone(),
            session: self.session.clone(),
        }
    }
}

impl Debug for FederatedUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("FederatedUser")
            .field("partition", &self.partition)
            .field("account_id", &self.account_id)
            .field("user_name", &self.user_name)
            .field("session", &self.session)
            .finish()
    }
}

impl Hash for FederatedUser {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.partition.hash(state);
        self.account_id.hash(state);
        self.user_name.hash(state);
    }
}

impl PartialEq for FederatedUser {
    fn eq(&self, other: &Self) -> bool {
        self.partition == other.partition && self.account_id == other.account_id && self.user_name == other.user_name
    }
}

impl Eq for FederatedUser {}

impl ToArn for FederatedUser {
    fn to_arn(&self) -> String {
        format!("arn:{}:sts::{}:federated-user/{}", self.partition, self.account_id, self.user_name)
    }
}

impl Display for FederatedUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(&self.to_arn().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::SessionData, FederatedUser};

    #[test]
    fn check_valid_federated_users() {
        let f1 = FederatedUser::new("aws", "123456789012", "user@domain", SessionData::new()).unwrap();

        assert_eq!(f1.to_string(), "arn:aws:sts::123456789012:federated-user/user@domain");

        let f2 =
            FederatedUser::new("partition-with-32-characters1234", "123456789012", "user@domain", SessionData::new())
                .unwrap();
        assert_eq!(f2.to_string(), "arn:partition-with-32-characters1234:sts::123456789012:federated-user/user@domain");

        assert_ne!(f1, f2);

        assert_eq!(
            FederatedUser::new("aws", "123456789012", "user@domain-with_32-characters==", SessionData::new(),)
                .unwrap()
                .to_string(),
            "arn:aws:sts::123456789012:federated-user/user@domain-with_32-characters=="
        );

        let f1_clone = f1.clone();
        assert!(f1 == f1_clone);

        // Make sure we can debug the federated user.
        let _ = format!("{:?}", f1);
    }

    #[test]
    fn check_invalid_federated_users() {
        assert_eq!(
            FederatedUser::new("", "123456789012", "user@domain", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid partition: """#
        );

        assert_eq!(
            FederatedUser::new("aws", "", "user@domain", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid account id: """#
        );

        assert_eq!(
            FederatedUser::new("aws", "123456789012", "", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid federated user name: """#
        );

        assert_eq!(
            FederatedUser::new("aws", "123456789012", "user!name@domain", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid federated user name: "user!name@domain""#
        );

        assert_eq!(
            FederatedUser::new("aws", "123456789012", "u", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid federated user name: "u""#
        );

        assert_eq!(
            FederatedUser::new("partition-with-33-characters12345", "123456789012", "user@domain", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "partition-with-33-characters12345""#
        );

        assert_eq!(
            FederatedUser::new("aws", "1234567890123", "user@domain", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid account id: "1234567890123""#
        );

        assert_eq!(
            FederatedUser::new("aws", "123456789012", "user@domain-with-33-characters===", SessionData::new(),)
                .unwrap_err()
                .to_string(),
            r#"Invalid federated user name: "user@domain-with-33-characters===""#
        );
    }
}
