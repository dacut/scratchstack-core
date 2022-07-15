use {
    super::SessionData,
    crate::{
        utils::{validate_account_id, validate_identifier, validate_name, validate_partition, validate_path},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
    },
};

/// Details about an AWS IAM user.
pub struct User {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// Path, starting with a `/`.
    path: String,

    /// The unqiue id of the user.
    user_id: String,

    /// Name of the principal, case-insensitive.
    user_name: String,

    /// Session details about the user.
    session: SessionData,
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
    /// * `user_id`: The unique id of the user. This must be a 20 character identifier beginning with `AIDA`
    ///    in base-32 format or a [PrincipalError::InvalidRoleId] error will be returned.
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
    pub fn new(
        partition: &str,
        account_id: &str,
        path: &str,
        user_id: &str,
        user_name: &str,
        session: SessionData,
    ) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_identifier(user_id, "AIDA", PrincipalError::InvalidUserId)?;
        validate_path(path)?;
        validate_name(user_name, 64, PrincipalError::InvalidUserName)?;

        Ok(Self {
            partition: partition.into(),
            account_id: account_id.into(),
            path: path.into(),
            user_id: user_id.into(),
            user_name: user_name.into(),
            session: session,
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
    pub fn path(&self) -> &str {
        &self.path
    }

    #[inline]
    pub fn user_id(&self) -> &str {
        &self.user_id
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

impl Clone for User {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            account_id: self.account_id.clone(),
            path: self.path.clone(),
            user_id: self.user_id.clone(),
            user_name: self.user_name.clone(),
            session: self.session.clone(),
        }
    }
}

impl Debug for User {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("User")
            .field("partition", &self.partition)
            .field("account_id", &self.account_id)
            .field("path", &self.path)
            .field("user_id", &self.user_id)
            .field("user_name", &self.user_name)
            .field("session", &self.session)
            .finish()
    }
}

impl Hash for User {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.partition.hash(state);
        self.account_id.hash(state);
        self.path.hash(state);
        self.user_id.hash(state);
        self.user_name.hash(state);
    }
}

impl PartialEq for User {
    fn eq(&self, other: &Self) -> bool {
        self.partition == other.partition
            && self.account_id == other.account_id
            && self.path == other.path
            && self.user_id == other.user_id
            && self.user_name == other.user_name
    }
}

impl Eq for User {}

impl ToArn for User {
    fn to_arn(&self) -> String {
        format!("arn:aws:iam::{}:user{}{}", self.account_id, self.path, self.user_name)
    }
}

impl Display for User {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.write_str(self.to_arn().as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{super::SessionData, User};

    #[test]
    fn check_valid_users() {
        let user1 =
            User::new("aws", "123456789012", "/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new()).unwrap();
        assert_eq!(user1.to_string(), "arn:aws:iam::123456789012:user/user-name");

        let user2 = User::new(
            "aws",
            "123456789012",
            "/",
            "AIDAA2B3C4D5E6F7HIJK",
            "user-name_is@ok.with,accepted=symbols",
            SessionData::new(),
        )
        .unwrap();

        assert_eq!(user2.to_string(), "arn:aws:iam::123456789012:user/user-name_is@ok.with,accepted=symbols");

        assert_ne!(user1, user2);

        User::new("aws", "123456789012", "/path/test/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
            .unwrap();

        User::new(
            "aws",
            "123456789012",
            "/path///multi-slash/test/",
            "AIDAA2B3C4D5E6F7HIJK",
            "user-name",
            SessionData::new(),
        )
        .unwrap();

        let user1 = User::new(
            "aws",
            "123456789012",
            "/!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~/",
            "AIDAA2B3C4D5E6F7HIJK",
            "user-name",
            SessionData::new(),
        )
        .unwrap();

        let user2 = User::new(
            "aws",
            "123456789012",
            "/",
            "AIDAA2B3C4D5E6F7HIJK",
            "user-name-with-64-characters====================================",
            SessionData::new(),
        )
        .unwrap();
        User::new("aws", "123456789012", "/", "AIDALMNOPQRSTUVWXY23", "user-name", SessionData::new()).unwrap();

        assert_ne!(user1, user2);

        let user1_clone = user1.clone();
        assert_eq!(user1, user1_clone);

        // Make sure we can debug a user.
        let _ = format!("{:?}", user1);
    }

    #[test]
    fn check_invalid_users() {
        assert_eq!(
            User::new("", "123456789012", "/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: """#
        );

        assert_eq!(
            User::new("aws", "", "/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid account id: """#
        );

        assert_eq!(
            User::new("aws", "123456789012", "", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid path: """#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/", "AIDAA2B3C4D5E6F7HIJK", "", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid user name: """#
        );

        assert_eq!(
            User::new(
                "aws",
                "123456789012",
                "/",
                "AIDAA2B3C4D5E6F7HIJK",
                "user-name-with-65-characters=====================================",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid user name: "user-name-with-65-characters=====================================""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/", "AIDAA2B3C4D5E6F7HIJK", "user!name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid user name: "user!name""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/", "", "user-name", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid user id: """#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/", "AGPAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid user id: "AGPAA2B3C4D5E6F7HIJK""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/", "AIDA________________", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid user id: "AIDA________________""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "path/test/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid path: "path/test/""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/path/test", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid path: "/path/test""#
        );

        assert_eq!(
            User::new("aws", "123456789012", "/path test/", "AIDAA2B3C4D5E6F7HIJK", "user-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid path: "/path test/""#
        );
    }
}
