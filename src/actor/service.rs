use {
    super::SessionData,
    crate::{
        utils::{validate_dns, validate_region},
        PrincipalError,
    },
    std::{
        fmt::{Display, Formatter, Result as FmtResult},
        hash::{Hash, Hasher},
    },
};

#[derive(Clone, Debug)]
/// Details about a service. Requires the `service` feature.
pub struct Service {
    /// Name of the service.
    service_name: String,

    /// The region the service is running in. If None, the service is global.
    region: Option<String>,

    /// The DNS suffix of the service. This is usually amazonaws.com.
    dns_suffix: String,

    /// Session data about the service.
    session: SessionData,
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
    pub fn new(
        service_name: &str,
        region: Option<String>,
        dns_suffix: &str,
        session: SessionData,
    ) -> Result<Self, PrincipalError> {
        validate_dns(service_name, 32, PrincipalError::InvalidServiceName)?;
        validate_dns(dns_suffix, 128, PrincipalError::InvalidServiceName)?;

        let region = match region {
            None => None,
            Some(region) => {
                validate_region(region.as_str())?;
                validate_dns(region.as_str(), 32, PrincipalError::InvalidServiceName)?;
                Some(region)
            }
        };

        Ok(Self {
            service_name: service_name.into(),
            region: region,
            dns_suffix: dns_suffix.into(),
            session: session,
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

    #[inline]
    pub fn session(&self) -> &SessionData {
        &self.session
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

impl PartialEq<Service> for Service {
    fn eq(&self, other: &Service) -> bool {
        self.service_name == other.service_name && self.region == other.region && self.dns_suffix == other.dns_suffix
    }
}

impl Eq for Service {}

impl Hash for Service {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.service_name.hash(state);
        self.region.hash(state);
        self.dns_suffix.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::{super::SessionData, Service};

    #[test]
    fn check_valid_services() {
        let service1 = Service::new("service-name", None, "amazonaws.com", SessionData::new()).unwrap();
        assert_eq!(service1.to_string(), "service-name.amazonaws.com");

        let service2 =
            Service::new("service-name2", None, "amazonaws.com", SessionData::new()).unwrap();
        assert_eq!(service2.to_string(), "service-name2.amazonaws.com");

        assert_ne!(service1, service2);

        assert_eq!(
            Service::new("service-name", Some("us-east-1".to_string()), "amazonaws.com", SessionData::new())
                .unwrap()
                .to_string(),
            "service-name.us-east-1.amazonaws.com"
        );

        assert_eq!(
            Service::new("aservice-name-with-32-characters", None, "amazonaws.com", SessionData::new())
                .unwrap()
                .to_string(),
            "aservice-name-with-32-characters.amazonaws.com"
        );

        let service1_clone = service1.clone();
        assert_eq!(service1, service1_clone);

        // Make sure we can debug a service.
        let _ = format!("{:?}", service1);
    }

    #[test]
    fn check_invalid_services() {
        assert_eq!(
            Service::new("service name", None, "amazonaws.com", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service name", Some("us-east-1".to_string()), "amazonaws.com", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service!name", None, "amazonaws.com", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::new("service!name", Some("us-east-1".to_string()), "amazonaws.com", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::new("", None, "amazonaws.com", SessionData::new()).unwrap_err().to_string(),
            r#"Invalid service name: """#
        );

        assert_eq!(
            Service::new("a-service-name-with-33-characters", None, "amazonaws.com", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid service name: "a-service-name-with-33-characters""#
        );

        assert_eq!(
            Service::new("service-name", Some("us-east-".to_string()), "amazonaws.com", SessionData::new())
                .unwrap_err()
                .to_string(),
            r#"Invalid region: "us-east-""#
        );
    }
}
