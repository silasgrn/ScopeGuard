use std::process::Command;

use crate::finding::{Finding, Severity};

pub struct ListeningService {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub exposed: bool,
}

fn parse_listening_services(output: &str) -> Vec<ListeningService> {
    output
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 5 {
                return None;
            }
            let proto = columns[0].to_string();
            let local_address = columns[4];
            let (address, port) = local_address.rsplit_once(':').unwrap_or((local_address, "0"));
            let port = port.parse::<u16>().unwrap_or(0);
            let exposed = address == "0.0.0.0" || address == "::" || address == ":::";

            Some(ListeningService {
                protocol: proto,
                address: address.to_string(),
                port,
                exposed,
            })
        })
        .collect()
}

fn check_public_bindings(services: &[ListeningService]) -> Vec<Finding> {
    services
        .iter()
        .filter(|service| service.exposed)
        .map(|service| Finding {
            title: format!("Public service listening on {}:{}", service.protocol, service.port),
            description: format!("A {} service is listening on {}:{}.", service.protocol, service.address, service.port),
            risk: "Services exposed on public interfaces can be reached from untrusted networks.".to_string(),
            recommendation: "Validate whether this service should be publicly reachable or restrict it to localhost.".to_string(),
            severity: Severity::High,
            category: "Network Security".to_string(),
        })
        .collect()
}

pub fn run_network_audit() -> Vec<Finding> {
    let mut findings = Vec::new();

    if let Ok(output) = Command::new("ss").arg("-tuln").output() {
        if output.status.success() {
            let content = String::from_utf8_lossy(&output.stdout);
            let services = parse_listening_services(&content);
            findings.extend(check_public_bindings(&services));

            if findings.is_empty() {
                findings.push(Finding {
                    title: "Network audit placeholder".to_string(),
                    description: "No publicly exposed listeners were detected during the sample network scan.".to_string(),
                    risk: "Network listeners are being inspected, but more in-depth service matching is required.".to_string(),
                    recommendation: "Extend network discovery to identify service types and local-only bindings.".to_string(),
                    severity: Severity::Info,
                    category: "Network Security".to_string(),
                });
            }
        } else {
            findings.push(Finding {
                title: "Network listener scan failed".to_string(),
                description: "The ss command could not enumerate listening sockets.".to_string(),
                risk: "Failed network discovery may hide services bound to public interfaces.".to_string(),
                recommendation: "Ensure the ss utility is installed and accessible to the current user.".to_string(),
                severity: Severity::Medium,
                category: "Network Security".to_string(),
            });
        }
    } else {
        findings.push(Finding {
            title: "Network scanner unavailable".to_string(),
            description: "The system does not appear to have the ss utility installed.".to_string(),
            risk: "Without socket inspection, service exposure cannot be reliably assessed.".to_string(),
            recommendation: "Install iproute2 or another socket inspection tool before rerunning the audit.".to_string(),
            severity: Severity::Info,
            category: "Network Security".to_string(),
        });
    }

    findings
}
