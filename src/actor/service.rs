use {
    crate::{
        utils::{validate_dns, validate_region},
        PrincipalError,
    },
    std::fmt::{Display, Formatter, Result as FmtResult},
};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
    /// * `region`: The region the service is running in. If None, the service is global.
    /// * `dns_suffix`: The DNS suffix of the service. This is usually amazonaws.com.
    ///
    /// If all of the requirements are met, a [ServiceDetails] object is returned.  Otherwise, a [PrincipalError]
    /// error is returned.
    pub fn new(service_name: &str, region: Option<String>, dns_suffix: &str) -> Result<Self, PrincipalError> {
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

#[cfg(test)]
mod tests {
    use super::Service;

    #[test]
    fn check_valid_services() {
        let service1 = Service::new("service-name", None, "amazonaws.com").unwrap();
        assert_eq!(service1.to_string(), "service-name.amazonaws.com");

        let service2 = Service::new("service-name2", None, "amazonaws.com").unwrap();
        assert_eq!(service2.to_string(), "service-name2.amazonaws.com");

        assert_ne!(service1, service2);

        assert_eq!(
            Service::new("service-name", Some("us-east-1".to_string()), "amazonaws.com",).unwrap().to_string(),
            "service-name.us-east-1.amazonaws.com"
        );

        assert_eq!(
            Service::new("aservice-name-with-32-characters", None, "amazonaws.com",).unwrap().to_string(),
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
            Service::new("service name", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service name", Some("us-east-1".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service name""#
        );

        assert_eq!(
            Service::new("service!name", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(
            Service::new("service!name", Some("us-east-1".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "service!name""#
        );

        assert_eq!(Service::new("", None, "amazonaws.com",).unwrap_err().to_string(), r#"Invalid service name: """#);

        assert_eq!(
            Service::new("a-service-name-with-33-characters", None, "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid service name: "a-service-name-with-33-characters""#
        );

        assert_eq!(
            Service::new("service-name", Some("us-east-".to_string()), "amazonaws.com",).unwrap_err().to_string(),
            r#"Invalid region: "us-east-""#
        );
    }
}
