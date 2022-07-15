use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// Errors that can be raise during the parsing of principals.
#[derive(Debug)]
pub enum PrincipalError {
    /// Invalid ARN. The argument contains the specified ARN.
    InvalidArn(String),

    /// Invalid partition. The argument contains the specified partition.
    InvalidPartition(String),

    /// Invalid AWS account id. The argument contains the specified account id.
    InvalidAccountId(String),

    /// Invalid federated user name. The argument contains the specified user name.
    InvalidFederatedUserName(String),

    /// Invalid group name. The argument contains the specified group name.
    InvalidGroupName(String),

    /// Invalid group id. The argument contains the specified group id.
    InvalidGroupId(String),

    /// Invalid instance profile name. The argument contains the specified instance profile name.
    InvalidInstanceProfileName(String),

    /// Invalid instance profile id. The argument contains the specified instance profile id.
    InvalidInstanceProfileId(String),

    /// Invalid IAM path. The argument contains the specified path.
    InvalidPath(String),

    /// Invalid region. The argument contains the specified region.
    InvalidRegion(String),

    /// Invalid role name. The argument contains the specified role name.
    InvalidRoleName(String),

    /// Invalid role id. The argument contains the specified role id.
    InvalidRoleId(String),

    /// Invalid service name. The argument contains the specified service name.
    InvalidServiceName(String),

    /// Invalid session name. The argument contains the specified session name.
    InvalidSessionName(String),

    /// Invalid user name. The argument contains the specified user name.
    InvalidUserName(String),

    /// Invalid user id. The argument contains the specified user id.
    InvalidUserId(String),
}

impl Error for PrincipalError {}

impl Display for PrincipalError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            Self::InvalidArn(arn) => write!(f, "Invalid ARN: {:#?}", arn),
            Self::InvalidPartition(partition) => write!(f, "Invalid partition: {:#?}", partition),
            Self::InvalidAccountId(account_id) => {
                write!(f, "Invalid account id: {:#?}", account_id)
            }
            Self::InvalidFederatedUserName(user_name) => {
                write!(f, "Invalid federated user name: {:#?}", user_name)
            }
            Self::InvalidGroupName(group_name) => {
                write!(f, "Invalid group name: {:#?}", group_name)
            }
            Self::InvalidGroupId(group_id) => write!(f, "Invalid group id: {:#?}", group_id),
            Self::InvalidInstanceProfileName(instance_profile_name) => {
                write!(f, "Invalid instance profile name: {:#?}", instance_profile_name)
            }
            Self::InvalidInstanceProfileId(instance_profile_id) => {
                write!(f, "Invalid instance profile id: {:#?}", instance_profile_id)
            }
            Self::InvalidPath(path) => write!(f, "Invalid path: {:#?}", path),
            Self::InvalidRegion(region) => write!(f, "Invalid region: {:#?}", region),
            Self::InvalidRoleName(role_name) => write!(f, "Invalid role name: {:#?}", role_name),
            Self::InvalidRoleId(role_id) => write!(f, "Invalid role id: {:#?}", role_id),
            Self::InvalidServiceName(service_name) => {
                write!(f, "Invalid service name: {:#?}", service_name)
            }
            Self::InvalidSessionName(session_name) => {
                write!(f, "Invalid session name: {:#?}", session_name)
            }
            Self::InvalidUserName(user_name) => write!(f, "Invalid user name: {:#?}", user_name),
            Self::InvalidUserId(user_id) => write!(f, "Invalid user id: {:#?}", user_id),
        }
    }
}
