use crate::finding::{Finding, Severity};
use crate::scope::ScopeFile;

pub struct ServiceEntry {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub bound_to: String,
    pub exposed: bool,
    pub description: Option<String>,
}

impl ServiceEntry {
    fn from_scope(service: &crate::scope::ScopeService) -> Self {
        ServiceEntry {
            name: service.name.clone(),
            protocol: service.protocol.clone(),
            bound_to: service.host.clone(),
            port: service.port,
            exposed: service.exposed,
            description: service.description.clone(),
        }
    }
}

fn discover_services(scope: Option<&ScopeFile>) -> Vec<ServiceEntry> {
    scope
        .map(|scope| scope.services.iter().map(ServiceEntry::from_scope).collect())
        .unwrap_or_default()
}

pub fn run_services_audit(scope: Option<&ScopeFile>) -> Vec<Finding> {
    let services = discover_services(scope);
    let mut findings = Vec::new();

    for service in services {
        if service.exposed {
            let severity = if scope.is_some() {
                Severity::Info
            } else {
                Severity::High
            };

            findings.push(Finding {
                title: format!("Exposed service detected: {}", service.name),
                description: format!("Service {} is listening on {}:{}.", service.name, service.bound_to, service.port),
                risk: if scope.is_some() {
                    "This exposed service is declared in scope and should be reviewed for expected access.".to_string()
                } else {
                    "Publicly exposed services may be accessible to attackers if not protected.".to_string()
                },
                recommendation: if scope.is_some() {
                    "Verify that the declared scoped service is intentionally exposed and protected.".to_string()
                } else {
                    "Verify whether this service should be accessible externally and apply access controls.".to_string()
                },
                severity,
                category: "Services".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "No exposed services discovered".to_string(),
            description: "No exposed services were identified from the current scope or discovery data.".to_string(),
            risk: "No exposed services were found, but additional discovery coverage may still be needed.".to_string(),
            recommendation: "Extend service discovery to capture more local services and their exposure.".to_string(),
            severity: Severity::Info,
            category: "Services".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{ScopeFile, ScopeService};

    #[test]
    fn discover_services_returns_empty_without_scope() {
        let services = discover_services(None);
        assert!(services.is_empty());
    }

    #[test]
    fn run_services_audit_with_scope_reports_matching_service_as_info() {
        let scope = ScopeFile {
            services: vec![ScopeService {
                name: "my-service".to_string(),
                protocol: "tcp".to_string(),
                host: "0.0.0.0".to_string(),
                port: 9001,
                exposed: true,
                description: Some("Test service".to_string()),
            }],
        };

        let findings = run_services_audit(Some(&scope));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].title.contains("my-service"));
    }
}
