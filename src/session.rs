use std::collections::HashMap;

pub trait Session {
    /// The time that the multi-factor authentication (MFA) token was authenticated, in seconds since the Unix epoch.
    /// This provides the \${aws:MultiFactorAge} and \${aws:MultiFactorAuthPresent} Aspen policy variables.
    fn get_mfa_authentication_time(&self) -> Option<u64>;

    /// The time that the token was issued, in seconds from the Unix epoch. This provides the
    /// \${aws:TokenIssueTime} Aspen policy variable.
    fn get_token_issue_time(&self) -> Option<u64>;

    /// The time that the token will expire, in seconds from the Unix epoch.
    fn get_token_expire_time(&self) -> Option<u64>;

    /// The policy document for the session.
    fn get_policy_document(&self) -> Option<String>;

    /// The policy ARNs for the session.
    fn get_policy_arns(&self) -> Option<Vec<String>>;

    /// The tags passed in to the session.
    fn get_session_tags(&self) -> Option<HashMap<String, String>>;
}
