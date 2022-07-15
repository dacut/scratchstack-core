use crate::PrincipalError;

/// Verify that an account id meets AWS requirements.
///
/// An account id must be 12 ASCII digits.
///
/// If `account_id` meets this requirement, Ok is returned. Otherwise, a [PrincipalError::InvalidAccountId] error is
/// returned.
pub fn validate_account_id(account_id: &str) -> Result<(), PrincipalError> {
    let a_bytes = account_id.as_bytes();

    if a_bytes.len() != 12 {
        return Err(PrincipalError::InvalidAccountId(account_id.to_string()));
    }

    for c in a_bytes.iter() {
        if !c.is_ascii_digit() {
            return Err(PrincipalError::InvalidAccountId(account_id.to_string()));
        }
    }

    Ok(())
}

/// Verify that an instance profile, group, role, or user name meets AWS requirements.
///
/// The [AWS requirements](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) are similar for
/// these names:
/// *   The name must contain between 1 and `max_length` characters.
/// *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
///
/// The `max_length` argument is specified as an argument to this function, but should be
///
/// [128 for instance profiles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateInstanceProfile.html),
/// [128 for IAM groups](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateGroup.html),
/// [64 for IAM roles](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html), and
/// [64 for IAM users](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateUser.html).
///
/// If `name` meets these requirements, `Ok(())` is returned. Otherwise, Err(map_err(name.to_string())) is returned.
pub fn validate_name<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    let n_bytes = name.as_bytes();
    let n_len = n_bytes.len();

    if n_len == 0 || n_len > max_length {
        return Err(map_err(name.to_string()));
    }

    // Check that all characters are alphanumeric or , - . = @ _
    for c in n_bytes {
        if !(c.is_ascii_alphanumeric()
            || *c == b','
            || *c == b'-'
            || *c == b'.'
            || *c == b'='
            || *c == b'@'
            || *c == b'_')
        {
            return Err(map_err(name.to_string()));
        }
    }

    Ok(())
}

/// Verify that an instance profile id, group id, role id, or user id meets AWS requirements.
///
/// AWS only stipulates the first four characters of the ID as a type identifier; however, all IDs follow a common
/// convention of being 20 character base-32 strings. We enforce the prefix, length, and base-32 requirements here.
///
/// If `identifier` meets these requirements, Ok is returned. Otherwise, Err(map_err(id.to_string())) is returned.
pub fn validate_identifier<F: FnOnce(String) -> PrincipalError>(
    id: &str,
    prefix: &str,
    map_err: F,
) -> Result<(), PrincipalError> {
    if !id.starts_with(prefix) || id.len() != 20 {
        Err(map_err(id.to_string()))
    } else {
        for c in id.as_bytes() {
            // Must be base-32 encoded.
            if !(c.is_ascii_alphabetic() || (b'2'..=b'7').contains(c)) {
                return Err(map_err(id.to_string()));
            }
        }

        Ok(())
    }
}

/// Verify that a partition name meets the naming requirements.
///
/// AWS does not publish a formal specification for partition names. In this validator, we specify:
/// *   The partition must be composed of ASCII alphanumeric characters or `-`.
/// *   The partition must have between 1 and 32 characters.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// If `partition` meets the requirements, Ok is returned. Otherwise, a [PrincipalError::InvalidPartition] error is
/// returned.
pub fn validate_partition(partition: &str) -> Result<(), PrincipalError> {
    let p_bytes = partition.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 32 {
        return Err(PrincipalError::InvalidPartition(partition.to_string()));
    }

    let mut last_was_dash = false;
    for (i, c) in p_bytes.iter().enumerate() {
        if *c == b'-' {
            if i == 0 || i == p_len - 1 || last_was_dash {
                return Err(PrincipalError::InvalidPartition(partition.to_string()));
            }

            last_was_dash = true;
        } else if !c.is_ascii_alphanumeric() {
            return Err(PrincipalError::InvalidPartition(partition.to_string()));
        } else {
            last_was_dash = false;
        }
    }

    Ok(())
}

/// Verify that a path meets AWS requirements.
///
/// The [AWS requirements for a path](https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateRole.html) specify:
/// *   The path must contain between 1 and 512 characters.
/// *   The path must start and end with `/`.
/// *   All characters in the path must be in the ASCII range 0x21 (`!`) through 0x7E (`~`). The AWS documentation
///     erroneously indicates that 0x7F (DEL) is acceptable; however, the IAM APIs reject this character.
///
/// If `path` meets these requirements, Ok. Otherwise, a [PrincipalError::InvalidPath] error is returned.
pub fn validate_path(path: &str) -> Result<(), PrincipalError> {
    let p_bytes = path.as_bytes();
    let p_len = p_bytes.len();

    if p_len == 0 || p_len > 512 {
        return Err(PrincipalError::InvalidPath(path.to_string()));
    }

    // Must begin and end with a slash
    if p_bytes[0] != b'/' || p_bytes[p_len - 1] != b'/' {
        return Err(PrincipalError::InvalidPath(path.to_string()));
    }

    // Check that all characters fall in the fange u+0021 - u+007e
    for c in p_bytes {
        if *c < 0x21 || *c > 0x7e {
            return Err(PrincipalError::InvalidPath(path.to_string()));
        }
    }

    Ok(())
}

#[derive(PartialEq)]
enum RegionParseState {
    Start,
    LastWasAlpha,
    LastWasDash,
    LastWasDigit,
}

enum RegionParseSection {
    Region,
    LocalRegion,
}

/// Verify that a region name meets the naming requirements.
///
/// AWS does not publish a formal specification for region names. In this validator, we specify:
/// *   The region must be composed of ASCII alphabetic characters or `-`. followed by a `-` and one or more digits,
///     or the name `"local"`.
/// *   The region can have a local region appended to it: a `-`, one or more ASCII alphabetic characters or `-`.
///     followed by a `-` and one or more digits.
/// *   A `-` cannot appear in the first or last position, nor can it appear in two consecutive characters.
///
/// If `region` meets the requirements, Ok is returned. Otherwise, a [PrincipalError::InvalidRegion] error is
/// returned.
pub fn validate_region(region: &str) -> Result<(), PrincipalError> {
    let r_bytes = region.as_bytes();

    // As a special case, we accept the region "local"
    if region == "local" {
        return Ok(());
    }

    let mut section = RegionParseSection::Region;
    let mut state = RegionParseState::Start;

    for c in r_bytes {
        if c == &b'-' {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash => {
                    return Err(PrincipalError::InvalidRegion(region.to_string()));
                }
                RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasDash;
                }
                RegionParseState::LastWasDigit => match section {
                    RegionParseSection::Region => {
                        section = RegionParseSection::LocalRegion;
                        state = RegionParseState::LastWasDash;
                    }
                    RegionParseSection::LocalRegion => {
                        return Err(PrincipalError::InvalidRegion(region.to_string()));
                    }
                },
            }
        } else if c.is_ascii_lowercase() {
            match state {
                RegionParseState::Start | RegionParseState::LastWasDash | RegionParseState::LastWasAlpha => {
                    state = RegionParseState::LastWasAlpha;
                }
                _ => {
                    return Err(PrincipalError::InvalidRegion(region.to_string()));
                }
            }
        } else if c.is_ascii_digit() {
            match state {
                RegionParseState::LastWasDash | RegionParseState::LastWasDigit => {
                    state = RegionParseState::LastWasDigit;
                }
                _ => {
                    return Err(PrincipalError::InvalidRegion(region.to_string()));
                }
            }
        } else {
            return Err(PrincipalError::InvalidRegion(region.to_string()));
        }
    }

    if state == RegionParseState::LastWasDigit {
        Ok(())
    } else {
        Err(PrincipalError::InvalidRegion(region.to_string()))
    }
}

pub fn validate_dns<F: FnOnce(String) -> PrincipalError>(
    name: &str,
    max_length: usize,
    map_err: F,
) -> Result<(), PrincipalError> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() == 0 || name_bytes.len() > max_length {
        return Err(map_err(name.to_string()));
    }

    let mut last = None;

    for (i, c) in name_bytes.iter().enumerate() {
        if *c == b'-' || *c == b'.' {
            if i == 0 || i == name_bytes.len() - 1 || last == Some(b'-') || last == Some(b'.') {
                return Err(map_err(name.to_string()));
            }
        } else if !c.is_ascii_alphanumeric() {
            return Err(map_err(name.to_string()));
        }

        last = Some(*c);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::{validate_name, validate_region, PrincipalError};

    #[test]
    fn check_regions() {
        validate_region("us-west-2").unwrap();

        validate_region("us-west-2-lax-1").unwrap();

        validate_region("local").unwrap();

        assert_eq!(validate_region("us-").unwrap_err().to_string(), r#"Invalid region: "us-""#);

        assert_eq!(validate_region("us-west").unwrap_err().to_string(), r#"Invalid region: "us-west""#);

        assert_eq!(validate_region("-us-west-2").unwrap_err().to_string(), r#"Invalid region: "-us-west-2""#);

        assert_eq!(
            validate_region("us-west-2-lax-1-lax-2").unwrap_err().to_string(),
            r#"Invalid region: "us-west-2-lax-1-lax-2""#
        );

        assert_eq!(validate_region("us-west-2a").unwrap_err().to_string(), r#"Invalid region: "us-west-2a""#);

        assert_eq!(validate_region("us-west2").unwrap_err().to_string(), r#"Invalid region: "us-west2""#);

        assert_eq!(validate_region("us-west*").unwrap_err().to_string(), r#"Invalid region: "us-west*""#);

        let err = validate_region("us-west-2-").unwrap_err();
        let _ = format!("{:?}", err); // Make sure PrincipalErrors can be debugged.
    }

    #[test]
    fn check_names() {
        validate_name("test", 32, PrincipalError::InvalidRoleName).unwrap();
        validate_name("test,name-.with=exactly@32_chars", 32, PrincipalError::InvalidRoleName).unwrap();
        assert_eq!(
            validate_name("bad!name", 32, PrincipalError::InvalidRoleName).unwrap_err().to_string(),
            r#"Invalid role name: "bad!name""#
        );
    }
}
