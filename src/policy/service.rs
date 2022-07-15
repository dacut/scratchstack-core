use {
    super::MatchesActor,
    crate::{
        actor,
        utils::{validate_name, validate_region},
        PrincipalError, TryToArn,
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
/// Details about a service. Requires the `service` feature.
pub struct Service {
    /// Name of the service.
    service_name: String,

    /// The region the service is running in. If None, the service is global.
    region: Option<String>,

    /// The DNS suffix of the service. This is usually amazonaws.com.
    dns_suffix: String,
}

impl Service {
    /// Create a [ServiceDetails] object. Requires the `service` feature.
    ///
    /// # Arguments
    ///
    /// * `service_name`: The name of the service. This must meet the following requirements or a
    ///     [PrincipalError::InvalidServiceName] error will be returned:
    ///     *   The name must contain between 1 and 32 characters.
    ///     *   The name must be composed to ASCII alphanumeric characters or one of `, - . = @ _`.
    ///
    /// If all of the requirements are met, a [ServiceDetails] object is returned.  Otherwise, a [PrincipalError]
    /// error is returned.
    pub fn new(service_name: &str, region: Option<String>, dns_suffix: &str) -> Result<Self, PrincipalError> {
        validate_name(service_name, 32, PrincipalError::InvalidServiceName)?;

        let region = match region {
            None => None,
            Some(region) => {
                validate_region(region.as_str())?;
                Some(region)
            }
        };

        Ok(Self {
            service_name: service_name.into(),
            region: region,
            dns_suffix: dns_suffix.into(),
        })
    }

    #[inline]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    #[inline]
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }

    #[inline]
    pub fn dns_suffix(&self) -> &str {
        &self.dns_suffix
    }
}

impl Display for Service {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.region {
            None => write!(f, "{}.{}", self.service_name, self.dns_suffix),
            Some(region) => write!(f, "{}.{}.{}", self.service_name, region, self.dns_suffix),
        }
    }
}

impl TryToArn for Service {
    fn try_to_arn(&self) -> Option<String> {
        None
    }
}

impl MatchesActor<actor::Principal> for Service {
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

impl MatchesActor<actor::AssumedRole> for Service {
    fn matches(&self, _: &actor::AssumedRole) -> bool {
        false
    }
}

impl MatchesActor<actor::FederatedUser> for Service {
    fn matches(&self, _: &actor::FederatedUser) -> bool {
        false
    }
}

impl MatchesActor<actor::RootUser> for Service {
    fn matches(&self, _: &actor::RootUser) -> bool {
        false
    }
}

impl MatchesActor<actor::Service> for Service {
    fn matches(&self, other: &actor::Service) -> bool {
        self.service_name == other.service_name()
            && self.dns_suffix == other.dns_suffix()
            && match (&self.region, other.region()) {
                (None, _) => true,
                (Some(self_region), Some(other_region)) => self_region == other_region,
                _ => false,
            }
    }
}

impl MatchesActor<actor::User> for Service {
    fn matches(&self, _: &actor::User) -> bool {
        false
    }
}
