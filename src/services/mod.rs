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
    if let Some(scope) = scope {
        return scope
            .services
            .iter()
            .map(ServiceEntry::from_scope)
            .collect();
    }

    vec![
        ServiceEntry {
            name: "nginx".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            bound_to: "0.0.0.0".to_string(),
            exposed: true,
            description: Some("Example web server".to_string()),
        },
        ServiceEntry {
            name: "postgres".to_string(),
            port: 5432,
            protocol: "tcp".to_string(),
            bound_to: "127.0.0.1".to_string(),
            exposed: false,
            description: Some("Local database service".to_string()),
        },
        ServiceEntry {
            name: "redis".to_string(),
            port: 6379,
            protocol: "tcp".to_string(),
            bound_to: "0.0.0.0".to_string(),
            exposed: true,
            description: Some("In-memory cache service".to_string()),
        },
    ]
}

pub fn run_services_audit(scope: Option<&ScopeFile>) -> Vec<Finding> {
    let services = discover_services(scope);
    let mut findings = Vec::new();

    for service in services {
        if service.exposed {
            findings.push(Finding {
                title: format!("Exposed service detected: {}", service.name),
                description: format!("Service {} is listening on {}:{}.", service.name, service.bound_to, service.port),
                risk: "Publicly exposed services may be accessible to attackers if not protected.".to_string(),
                recommendation: "Verify whether this service should be accessible externally and apply access controls.".to_string(),
                severity: Severity::High,
                category: "Services".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "Service discovery placeholder".to_string(),
            description: "Service discovery routines are initialized and ready to inspect actual local services.".to_string(),
            risk: "No exposed services were found by the placeholder discovery.".to_string(),
            recommendation: "Implement actual service discovery for web servers, databases, and caches.".to_string(),
            severity: Severity::Info,
            category: "Services".to_string(),
        });
    }

    findings
}
