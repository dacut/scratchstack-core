use {
    crate::{
        utils::{validate_account_id, validate_partition},
        PrincipalError, ToArn,
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

/// Details about an AWS account.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RootUser {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,
}

impl RootUser {
    /// Create a [RootUser] object, refering to an actor with root credentials for the specified
    /// AWS account.
    ///
    /// # Arguments
    ///
    /// * `partition` - The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    ///
    /// # Return value
    ///
    /// If the requirement is met, a [RootUserDetails] object is returned. Otherwise, a
    /// [PrincipalError] error is returned.
    pub fn new(partition: &str, account_id: &str) -> Result<Self, PrincipalError> {
        let partition = partition.into();
        let account_id = account_id.into();

        validate_partition(partition)?;
        validate_account_id(account_id)?;

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

impl ToArn for RootUser {
    fn to_arn(&self) -> String {
        format!("arn:aws:iam::{}:root", self.account_id)
    }
}

impl Display for RootUser {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::RootUser;

    #[test]
    fn check_valid_root_users() {
        let root1 = RootUser::new("aws", "123456789012").unwrap();
        assert_eq!(root1.to_string(), "arn:aws:iam::123456789012:root");

        let root2 = RootUser::new("aws", "123456789099").unwrap();
        assert_eq!(root2.to_string(), "arn:aws:iam::123456789099:root");

        assert_ne!(root1, root2);

        let root1_clone = root1.clone();
        assert_eq!(root1, root1_clone);

        // Make sure we can debug a root user.
        let _ = format!("{:?}", root1);
    }

    #[test]
    fn check_invalid_root_users() {
        assert_eq!(RootUser::new("", "123456789012",).unwrap_err().to_string(), r#"Invalid partition: """#);

        assert_eq!(RootUser::new("aws", "",).unwrap_err().to_string(), r#"Invalid account id: """#);
    }
}
