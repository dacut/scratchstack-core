use {
    crate::{
        utils::{validate_account_id, validate_identifier, validate_name, validate_partition},
        PrincipalError, ToArn,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
    },
};

/// Details about an assumed role actor.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

#[cfg(test)]
mod tests {
    use {
        super::AssumedRole,
        std::{cmp::Ordering, collections::HashMap},
    };

    #[test]
    fn check_valid_assumed_roles() {
        let r1a = AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "Role_name", "session_name").unwrap();

        let r1b = AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "Role_name", "session_name").unwrap();

        let r2 = AssumedRole::new(
            "aws2",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "Role@Foo=bar,baz_=world-1234",
            "Session@1234,_=-,.OK",
        )
        .unwrap();

        assert_eq!(r1a, r1b);
        assert_ne!(r1a, r2);
        assert!(&r1a <= &r1b);
        assert!(&r1a >= &r1b);
        assert_eq!(r1a.partition(), "aws");
        assert_eq!(r1a.account_id(), "123456789012");
        assert_eq!(r1a.role_id(), "AROAAAAABBBBCCCCDDDD");
        assert_eq!(r1a.role_name(), "Role_name");
        assert_eq!(r1a.session_name(), "session_name");

        let mut hm = HashMap::new();
        hm.insert(r1a.clone(), "foo".to_string());
        hm.insert(r1b.clone(), "bar".to_string());

        assert_eq!(hm.get(&r1a).unwrap(), "bar");

        assert_eq!(r1a.partial_cmp(&r1b), Some(Ordering::Equal));
        assert!(&r1a < &r2);
        assert!(&r1a <= &r2);
        assert!(&r2 > &r1a);
        assert!(&r2 >= &r1a);
        assert!(&r2 != &r1a);

        assert_eq!(r1a.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(r1b.to_string(), "arn:aws:sts::123456789012:assumed-role/Role_name/session_name");
        assert_eq!(
            r2.to_string(),
            "arn:aws2:sts::123456789012:assumed-role/Role@Foo=bar,baz_=world-1234/Session@1234,_=-,.OK"
        );

        let r1c = r1a.clone();
        assert!(r1a == r1c);

        AssumedRole::new(
            "partition-with-32-characters1234",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name",
            "session_name",
        )
        .unwrap();

        AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name-with_64-characters====================================",
            "session@1234",
        )
        .unwrap();

        AssumedRole::new(
            "aws",
            "123456789012",
            "AROAAAAABBBBCCCCDDDD",
            "role-name",
            "session-name-with-64-characters=================================",
        )
        .unwrap();

        // Make sure we can debug the assumed role.
        let _ = format!("{:?}", r1a);
    }

    #[test]
    fn check_invalid_assumed_roles() {
        assert_eq!(
            AssumedRole::new("", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name").unwrap_err().to_string(),
            r#"Invalid account id: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "", "session-name")
                .unwrap_err()
                .to_string(),
            r#"Invalid role name: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "").unwrap_err().to_string(),
            r#"Invalid session name: """#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "s").unwrap_err().to_string(),
            r#"Invalid session name: "s""#
        );

        assert_eq!(
            AssumedRole::new(
                "partition-with-33-characters12345",
                "123456789012",
                "AROAAAAABBBBCCCCDDDD",
                "role-name",
                "session_name",
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid partition: "partition-with-33-characters12345""#
        );

        assert_eq!(
            AssumedRole::new("aws", "1234567890123", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
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
            )
            .unwrap_err()
            .to_string(),
            r#"Invalid session name: "session-name-with-65-characters==================================""#
        );

        assert_eq!(
            AssumedRole::new("-aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "-aws""#
        );

        assert_eq!(
            AssumedRole::new("aws-", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "aws-""#
        );

        assert_eq!(
            AssumedRole::new("aws--us", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "aws--us""#
        );

        assert_eq!(
            AssumedRole::new("aw!", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid partition: "aw!""#
        );

        assert_eq!(
            AssumedRole::new("aws", "a23456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid account id: "a23456789012""#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AIDAAAAABBBBCCCCDDDD", "role-name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid role id: "AIDAAAAABBBBCCCCDDDD""#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role+name", "session-name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid role name: "role+name""#
        );

        assert_eq!(
            AssumedRole::new("aws", "123456789012", "AROAAAAABBBBCCCCDDDD", "role-name", "session+name",)
                .unwrap_err()
                .to_string(),
            r#"Invalid session name: "session+name""#
        );
    }
}
