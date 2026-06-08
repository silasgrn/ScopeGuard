use std::process::Command;

use crate::finding::{Finding, Severity};

pub enum FirewallBackend {
    Nftables,
    Iptables,
    Unknown,
}

pub struct FirewallStatus {
    pub backend: FirewallBackend,
    pub rules_loaded: bool,
}

fn detect_firewall() -> FirewallStatus {
    if let Ok(output) = Command::new("nft").arg("list").arg("ruleset").output() {
        return FirewallStatus {
            backend: FirewallBackend::Nftables,
            rules_loaded: output.status.success(),
        };
    }

    if let Ok(output) = Command::new("iptables").arg("-L").output() {
        return FirewallStatus {
            backend: FirewallBackend::Iptables,
            rules_loaded: output.status.success(),
        };
    }

    FirewallStatus {
        backend: FirewallBackend::Unknown,
        rules_loaded: false,
    }
}

fn build_firewall_findings(status: FirewallStatus) -> Vec<Finding> {
    match status.backend {
        FirewallBackend::Nftables => {
            if status.rules_loaded {
                vec![Finding {
                    title: "nftables firewall detected".to_string(),
                    description: "The host has an nftables firewall backend configured.".to_string(),
                    risk: "A firewall backend is present but may still have permissive rules.".to_string(),
                    recommendation: "Review nftables policies and ensure default deny rules are enforced.".to_string(),
                    severity: Severity::Low,
                    category: "Firewall".to_string(),
                }]
            } else {
                vec![Finding {
                    title: "nftables ruleset unavailable".to_string(),
                    description: "The nftables backend is installed, but the ruleset could not be read.".to_string(),
                    risk: "Missing firewall rules may expose the host to network attacks.".to_string(),
                    recommendation: "Verify nftables configuration and permissions for ruleset inspection.".to_string(),
                    severity: Severity::Medium,
                    category: "Firewall".to_string(),
                }]
            }
        }
        FirewallBackend::Iptables => {
            if status.rules_loaded {
                vec![Finding {
                    title: "iptables firewall detected".to_string(),
                    description: "The host has an iptables firewall backend configured.".to_string(),
                    risk: "iptables is available but may still allow unwanted traffic if rules are too open.".to_string(),
                    recommendation: "Review iptables chains and default policies for accepted traffic.".to_string(),
                    severity: Severity::Low,
                    category: "Firewall".to_string(),
                }]
            } else {
                vec![Finding {
                    title: "iptables rules unavailable".to_string(),
                    description: "The iptables backend is available, but its rules could not be inspected.".to_string(),
                    risk: "Missing iptables visibility may hide misconfigurations.".to_string(),
                    recommendation: "Ensure iptables is installed and accessible to the current user.".to_string(),
                    severity: Severity::Medium,
                    category: "Firewall".to_string(),
                }]
            }
        }
        FirewallBackend::Unknown => vec![Finding {
            title: "No firewall backend detected".to_string(),
            description: "Neither nftables nor iptables were detected on this host.".to_string(),
            risk: "No detected firewall backend increases the risk of unmanaged network exposure.".to_string(),
            recommendation: "Install and configure nftables or iptables to protect the host.".to_string(),
            severity: Severity::High,
            category: "Firewall".to_string(),
        }],
    }
}

pub fn run_firewall_audit() -> Vec<Finding> {
    let status = detect_firewall();
    build_firewall_findings(status)
}
