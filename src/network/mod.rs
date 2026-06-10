use std::process::Command;

use crate::finding::{Finding, Severity};

fn run_command_with_sudo_fallback(cmd: &str, args: &[&str]) -> Option<String> {
    if let Ok(output) = Command::new(cmd).args(args).output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
    }

    if let Ok(output) = Command::new("sudo").args(["-n", cmd]).args(args).output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
    }

    if let Ok(output) = Command::new("sudo").arg(cmd).args(args).output() {
        if output.status.success() {
            return Some(String::from_utf8_lossy(&output.stdout).into_owned());
        }
    }

    None
}

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
            let (address, port) = local_address
                .rsplit_once(':')
                .unwrap_or((local_address, "0"));
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

    if let Some(content) = run_command_with_sudo_fallback("ss", &["-tuln"]) {
        let services = parse_listening_services(&content);
        findings.extend(check_public_bindings(&services));

        if findings.is_empty() {
            findings.push(Finding {
                title: "No publicly exposed listeners detected".to_string(),
                description: "The network scanner found no services bound to public interfaces.".to_string(),
                risk: "No publicly exposed listening sockets were identified during this scan.".to_string(),
                recommendation: "Review local-only bindings and verify the expected network exposure.".to_string(),
                severity: Severity::Info,
                category: "Network Security".to_string(),
            });
        }
    } else {
        findings.push(Finding {
            title: "Network listener scan failed".to_string(),
            description: "The ss command could not enumerate listening sockets, even with sudo fallback.".to_string(),
            risk: "Failed network discovery may hide services bound to public interfaces.".to_string(),
            recommendation:
                "Ensure the ss utility is installed and the scanner has permission to inspect sockets.".to_string(),
            severity: Severity::Medium,
            category: "Network Security".to_string(),
        });
    }

    findings
}
