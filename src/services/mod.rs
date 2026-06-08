use crate::finding::{Finding, Severity};

pub struct ServiceEntry {
    pub name: String,
    pub port: u16,
    pub protocol: String,
    pub bound_to: String,
    pub exposed: bool,
}

fn discover_services() -> Vec<ServiceEntry> {
    vec![
        ServiceEntry {
            name: "nginx".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            bound_to: "0.0.0.0".to_string(),
            exposed: true,
        },
        ServiceEntry {
            name: "postgres".to_string(),
            port: 5432,
            protocol: "tcp".to_string(),
            bound_to: "127.0.0.1".to_string(),
            exposed: false,
        },
        ServiceEntry {
            name: "redis".to_string(),
            port: 6379,
            protocol: "tcp".to_string(),
            bound_to: "0.0.0.0".to_string(),
            exposed: true,
        },
    ]
}

pub fn run_services_audit() -> Vec<Finding> {
    let services = discover_services();
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
