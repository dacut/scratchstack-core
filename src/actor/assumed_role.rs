use {
    super::SessionData,
    crate::{
        utils::{validate_account_id, validate_identifier, validate_name, validate_partition},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Debug, Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
    },
};

/// Details about an assumed role actor.
pub struct AssumedRole {
    /// The partition this principal exists in.
    partition: String,

    /// The account id.
    account_id: String,

    /// The unqiue id of the role.
    role_id: String,

    /// Name of the role, case-insensitive.
    role_name: String,

    /// Session name for the assumed role.
    session_name: String,

    /// Session data about the assumed role.
    session: SessionData,
}

impl AssumedRole {
    /// Create an [AssumedRole] object.
    ///
    /// # Arguments:
    ///
    /// * `partition`: The partition this principal exists in.
    /// * `account_id`: The 12 digit account id. This must be composed of 12 ASCII digits or a
    ///     [PrincipalError::InvalidAccountId] error will be returned.
    /// * `role_id`: The unique id of the role. This must be a 20 character identifier beginning with `AROA`
    ///    in base-32 format or a [PrincipalError::InvalidRoleId] error will be returned.
    /// * `role_name`: The name of the role being assumed. This must meet the following requirements or a
    ///     [PrincipalError::InvalidRoleName] error will be returned:
    ///     *   The name must contain between 1 and 64 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session_name`: A name to assign to the session. This must meet the following requirements or a
    ///     [PrincipalError::InvalidSessionName] error will be returned:
    ///     *   The session name must contain between 2 and 64 characters.
    ///     *   The session name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    /// * `session`: Session data about the assumed role.
    ///
    /// # Return value
    ///
    /// If all of the requirements are met, an [AssumedRole] object is returned. Otherwise,
    /// a [PrincipalError] error is returned.
    pub fn new(
        partition: &str,
        account_id: &str,
        role_id: &str,
        role_name: &str,
        session_name: &str,
        session: SessionData,
    ) -> Result<Self, PrincipalError> {
        validate_partition(partition)?;
        validate_account_id(account_id)?;
        validate_identifier(role_id, "AROA", PrincipalError::InvalidRoleId)?;
        validate_name(role_name, 64, PrincipalError::InvalidRoleName)?;
        validate_name(session_name, 64, PrincipalError::InvalidSessionName)?;

        if session_name.len() < 2 {
            Err(PrincipalError::InvalidSessionName(session_name.into()))
        } else {
            Ok(Self {
                partition: partition.into(),
                account_id: account_id.into(),
                role_id: role_id.into(),
                role_name: role_name.into(),
                session_name: session_name.into(),
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
    pub fn role_id(&self) -> &str {
        &self.role_id
    }

    #[inline]
    pub fn role_name(&self) -> &str {
        &self.role_name
    }

    #[inline]
    pub fn session_name(&self) -> &str {
        &self.session_name
    }

    #[inline]
    pub fn session(&self) -> &SessionData {
        &self.session
    }
}

impl Clone for AssumedRole {
    fn clone(&self) -> Self {
        Self {
            partition: self.partition.clone(),
            account_id: self.account_id.clone(),
            role_id: self.role_id.clone(),
            role_name: self.role_name.clone(),
            session_name: self.session_name.clone(),
            session: self.session.clone(),
        }
    }
}

impl Debug for AssumedRole {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        f.debug_struct("AssumedRole")
            .field("partition", &self.partition)
            .field("account_id", &self.account_id)
            .field("role_id", &self.role_id)
            .field("role_name", &self.role_name)
            .field("session_name", &self.session_name)
            .field("session", &self.session)
            .finish()
    }
}

impl Hash for AssumedRole {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.partition.hash(state);
        self.account_id.hash(state);
        self.role_id.hash(state);
        self.role_name.hash(state);
        self.session_name.hash(state);
    }
}

impl PartialEq for AssumedRole {
    fn eq(&self, other: &Self) -> bool {
        self.partition == other.partition
            && self.account_id == other.account_id
            && self.role_id == other.role_id
            && self.role_name == other.role_name
            && self.session_name == other.session_name
    }
}

impl Eq for AssumedRole {}

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

#[cfg(test)]
mod tests {
    use super::{super::SessionData, AssumedRole};

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "Role_name",
            "session_name",
            SessionData::new(),
        )
        .unwrap();

        let r1b = AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "Role_name",
            "session_name",
            SessionData::new(),
        )
        .unwrap();

        let r2 = AssumedRole::new(
            "a-very-long-partition1",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "Role@Foo=bar,baz_=world-1234",
            "Session@1234,_=-,.OK",
            SessionData::new(),
        )
        .unwrap();

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);

        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r1b.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(
            r2.to_string(),
            "arn:a-very-long-partition1:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK");

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        AssumedRole::new(
            "partition-with-32-characters1234",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name",
            "session_name",
            SessionData::new(),
        )
        .unwrap();

        AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name-with_64-characters====================================",
            "session@1234",
            SessionData::new(),
        )
        .unwrap();

        AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name",
            "session-name-with-64-characters=================================",
            SessionData::new(),
        )
        .unwrap();

        // Make sure we can debug the assumed role.
        let _ = format!("{:?}", r1a);
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(
            AssumedRole::new(
                "",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new(),
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid account id: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "", "session-name", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid role name: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid session name: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "s", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid session name: "s""#
        );

        assert_eq!(
            AssumedRole::new(
                "partition-with-33-characters12345",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session_name",
                SessionData::new(),
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "partition-with-33-characters12345""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "1234567890123",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid account id: "1234567890123""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name-with-65-characters=====================================",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid role name: "role-name-with-65-characters=====================================""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name-with-65-characters==================================",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid session name: "session-name-with-65-characters==================================""#
        );

        assert_eq!(
            AssumedRole::new(
                "-aws",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "-aws""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws-",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "aws-""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws--us",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "aws--us""#
        );

        assert_eq!(
            AssumedRole::new(
                "aw!",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "aw!""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "a23456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid account id: "a23456789012""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role+name",
                "session-name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid role name: "role+name""#
        );

        assert_eq!(
            AssumedRole::new(
                "aws",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session+name",
                SessionData::new()
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid session name: "session+name""#
        );
    }
}
