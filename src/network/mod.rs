use std::process::Command;

use crate::finding::{Finding, Severity};

fn run_command_with_sudo_fallback(cmd: &str, args: &[&str]) -> Option<String> {
    if let Ok(output) = Command::new(cmd).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    if let Ok(output) = Command::new("sudo").args(["-n", cmd]).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    if let Ok(output) = Command::new("sudo").arg(cmd).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    None
}

pub struct ListeningService {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub exposed: bool,
}

impl ListeningService {
    fn is_public(&self) -> bool {
        matches!(self.address.as_str(), "0.0.0.0" | "::" | "*" | "[::]")
    }
}

fn parse_listening_services(output: &str) -> Vec<ListeningService> {
    output
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 4
                || columns[0].eq_ignore_ascii_case("proto")
                || columns[0].eq_ignore_ascii_case("netid")
            {
                return None;
            }

            let proto = columns[0].to_string();
            let local_address = columns.iter().find(|col| col.contains(':'))?;
            let (address, port) = local_address
                .rsplit_once(':')
                .unwrap_or((local_address, "0"));
            let port = port.parse::<u16>().unwrap_or(0);
            let exposed = matches!(address, "0.0.0.0" | "::" | "*" | "[::]");

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
        .filter(|service| service.is_public())
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

fn check_high_risk_public_services(services: &[ListeningService]) -> Vec<Finding> {
    const HIGH_RISK_PORTS: &[(u16, &str)] = &[
        (22, "SSH"),
        (23, "Telnet"),
        (3306, "MySQL"),
        (5432, "PostgreSQL"),
        (6379, "Redis"),
        (27017, "MongoDB"),
        (9200, "Elasticsearch"),
        (5985, "WinRM"),
        (5986, "WinRM over HTTPS"),
        (3389, "RDP"),
    ];

    services
        .iter()
        .filter(|service| service.is_public())
        .filter_map(|service| {
            HIGH_RISK_PORTS
                .iter()
                .find(|(port, _)| *port == service.port)
                .map(|(_, name)| (service, *name))
        })
        .map(|(service, name)| Finding {
            title: format!("High-risk public service exposed: {} on port {}", name, service.port),
            description: format!("{} is listening publicly on {}:{}.", name, service.address, service.port),
            risk: format!("The public exposure of {} increases the chance of remote compromise.", name),
            recommendation: format!("Limit {} access to trusted networks or protect it with authentication and firewall rules.", name),
            severity: Severity::Critical,
            category: "Network Security".to_string(),
        })
        .collect()
}

fn check_many_public_listeners(services: &[ListeningService]) -> Option<Finding> {
    let public_count = services
        .iter()
        .filter(|service| service.is_public())
        .count();
    if public_count >= 5 {
        return Some(Finding {
            title: format!("{} public listeners detected", public_count),
            description: "Multiple services are listening on public interfaces.".to_string(),
            risk: "A large number of publicly exposed listeners increases the attack surface."
                .to_string(),
            recommendation:
                "Review all exposed services and close or restrict any unnecessary listeners."
                    .to_string(),
            severity: Severity::Medium,
            category: "Network Security".to_string(),
        });
    }
    None
}

pub fn run_network_audit() -> Vec<Finding> {
    let mut findings = Vec::new();

    let content = run_command_with_sudo_fallback("ss", &["-tuln"])
        .or_else(|| run_command_with_sudo_fallback("netstat", &["-tuln"]));

    if let Some(content) = content {
        let services = parse_listening_services(&content);
        findings.extend(check_public_bindings(&services));
        findings.extend(check_high_risk_public_services(&services));
        if let Some(finding) = check_many_public_listeners(&services) {
            findings.push(finding);
        }

        if findings.is_empty() {
            findings.push(Finding {
                title: "No publicly exposed listeners detected".to_string(),
                description: "The network scanner found no services bound to public interfaces."
                    .to_string(),
                risk: "No publicly exposed listening sockets were identified during this scan."
                    .to_string(),
                recommendation:
                    "Review local-only bindings and verify the expected network exposure."
                        .to_string(),
                severity: Severity::Info,
                category: "Network Security".to_string(),
            });
        }
    } else {
        findings.push(Finding {
            title: "Network listener scan failed".to_string(),
            description: "The ss/netstat command could not enumerate listening sockets, even with sudo fallback.".to_string(),
            risk: "Failed network discovery may hide services bound to public interfaces.".to_string(),
            recommendation: "Ensure ss or netstat is installed and the scanner has permission to inspect sockets.".to_string(),
            severity: Severity::Medium,
            category: "Network Security".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_listening_services_detects_public_and_ipv6_wildcards() {
        let output = "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n";
        let output = format!(
            "{}tcp   0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\nudp   0      0 :::53                   :::*                    LISTEN\n",
            output
        );
        let services = parse_listening_services(&output);

        assert_eq!(services.len(), 2);
        assert!(services[0].exposed);
        assert!(services[1].exposed);
        assert_eq!(services[0].port, 22);
        assert_eq!(services[1].port, 53);
    }

    #[test]
    fn check_high_risk_public_services_reports_ssh_and_db_ports() {
        let services = vec![
            ListeningService {
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                port: 22,
                exposed: true,
            },
            ListeningService {
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                port: 3306,
                exposed: true,
            },
        ];

        let findings = check_high_risk_public_services(&services);
        assert_eq!(findings.len(), 2);
        assert!(findings[0].title.contains("SSH"));
        assert!(findings[1].title.contains("MySQL"));
    }

    #[test]
    fn check_many_public_listeners_reports_when_threshold_exceeded() {
        let services = (1..=5)
            .map(|port| ListeningService {
                protocol: "tcp".to_string(),
                address: "0.0.0.0".to_string(),
                port,
                exposed: true,
            })
            .collect::<Vec<_>>();

        let finding = check_many_public_listeners(&services);
        assert!(finding.is_some());
        assert!(finding.unwrap().title.contains("5 public listeners"));
    }
}
