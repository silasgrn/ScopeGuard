use super::backend::{FirewallBackend, FirewallRule, FirewallStatus, parse_firewall_rules};
use crate::finding::{Finding, Severity};
use crate::scope::ScopeFile;

fn find_scope_match<'a>(
    rule: &FirewallRule,
    scope: Option<&'a ScopeFile>,
) -> Option<&'a crate::scope::ScopeService> {
    scope.and_then(|scope| {
        scope.services.iter().find(|service| {
            service.port == rule.port && service.protocol.eq_ignore_ascii_case(&rule.protocol)
        })
    })
}

fn rule_description(rule: &FirewallRule) -> String {
    format!(
        "Firewall accepts inbound {} traffic on port {} destined for {}.",
        rule.protocol.to_uppercase(),
        rule.port,
        rule.destination
    )
}

fn describe_backend_name(backend: &FirewallBackend) -> &'static str {
    match backend {
        FirewallBackend::Nftables => "nftables",
        FirewallBackend::Iptables => "iptables",
        FirewallBackend::Ufw => "ufw",
        FirewallBackend::Unknown => "firewall",
    }
}

fn is_public_rule(rule: &FirewallRule) -> bool {
    let dest = rule.destination.to_lowercase();
    dest == "0.0.0.0/0" || dest == "::/0" || dest == "anywhere" || dest.contains("/0")
}

pub fn build_firewall_findings(status: &FirewallStatus, scope: Option<&ScopeFile>) -> Vec<Finding> {
    if !status.is_backend_available() {
        return vec![Finding {
            title: "No firewall backend detected".to_string(),
            description: "Neither nftables nor iptables were detected on this host.".to_string(),
            risk: "No detected firewall backend increases the risk of unmanaged network exposure."
                .to_string(),
            recommendation: "Install and configure nftables or iptables to protect the host."
                .to_string(),
            severity: Severity::High,
            category: "Firewall".to_string(),
        }];
    }

    if !status.rules_loaded {
        return vec![Finding {
            title: format!(
                "{} ruleset unavailable",
                describe_backend_name(&status.backend)
            ),
            description: format!(
                "The {} backend is available, but the ruleset could not be read.",
                describe_backend_name(&status.backend)
            ),
            risk: "Missing firewall rules may expose the host to network attacks.".to_string(),
            recommendation: "Verify firewall configuration and permissions for ruleset inspection."
                .to_string(),
            severity: Severity::Medium,
            category: "Firewall".to_string(),
        }];
    }

    let rules = parse_firewall_rules(status);
    let mut findings = Vec::new();

    if status.has_permissive_default_policy() {
        findings.push(Finding {
            title: "Permissive firewall default policy".to_string(),
            description: format!(
                "The {} default inbound policy is configured to accept connections by default.",
                describe_backend_name(&status.backend)
            ),
            risk: "A permissive default firewall policy can allow unexpected inbound traffic and weaken rule-level protections."
                .to_string(),
            recommendation: "Change the default inbound policy to deny or drop, then allow only required services explicitly."
                .to_string(),
            severity: Severity::High,
            category: "Firewall".to_string(),
        });
    }

    if rules.is_empty() {
        if !findings.is_empty() {
            return findings;
        }

        return vec![Finding {
            title: format!(
                "{} firewall loaded",
                describe_backend_name(&status.backend)
            ),
            description:
                "The firewall backend is configured and no inbound accept rules were parsed."
                    .to_string(),
            risk: "No open service rules were detected in the current firewall configuration."
                .to_string(),
            recommendation:
                "Validate that the firewall is enforcing the expected allow/deny policy."
                    .to_string(),
            severity: Severity::Info,
            category: "Firewall".to_string(),
        }];
    }

    for rule in rules {
        let matching_service = find_scope_match(&rule, scope);
        let public_access = is_public_rule(&rule);
        let (severity, title, description, risk, recommendation) = if let Some(service) = matching_service {
            let title = format!(
                "Known scoped firewall service detected on port {}",
                rule.port
            );
            let description = format!(
                "Firewall rule matches scoped service '{}' and accepts inbound {} traffic on {}:{}.",
                service.name,
                rule.protocol.to_uppercase(),
                rule.destination,
                rule.port
            );
            let risk = if public_access {
                "A known scoped service is permitted from a broad source and should be limited to expected clients.".to_string()
            } else {
                "A known scoped service is permitted by the firewall. Confirm access controls are still appropriate.".to_string()
            };
            let recommendation = if public_access {
                "Restrict this rule to trusted source addresses or apply tighter scope controls for the exposed service.".to_string()
            } else {
                "If this service is intentionally exposed, ensure scope documentation stays up to date and access is restricted to expected clients.".to_string()
            };
            let severity = if public_access { Severity::Medium } else { Severity::Info };
            (severity, title, description, risk, recommendation)
        } else {
            let title = format!("Open firewall service detected on port {}", rule.port);
            let description = rule_description(&rule);
            let risk = if public_access {
                "An open firewall rule permits inbound traffic from any source and may expose the host to the internet.".to_string()
            } else {
                "An open firewall rule permits inbound traffic to an unsupervised port or protocol.".to_string()
            };
            let recommendation = if public_access {
                "Review this public-facing firewall rule and restrict it to trusted hosts or disable it if the service is unnecessary.".to_string()
            } else {
                "Review the firewall rule and close or restrict it if it does not match an expected service.".to_string()
            };
            (Severity::High, title, description, risk, recommendation)
        };

        findings.push(Finding {
            title,
            description,
            risk,
            recommendation,
            severity,
            category: "Firewall".to_string(),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::super::backend::{FirewallBackend, FirewallPolicy, FirewallStatus};
    use super::*;
    use crate::scope::ScopeFile;
    use crate::scope::ScopeService;

    #[test]
    fn nftables_rules_loaded_returns_nftables_findings() {
        let status = FirewallStatus {
            backend: FirewallBackend::Nftables,
            rules_loaded: true,
            raw_output: Some("table inet filter { chain input { type filter hook input priority 0; tcp dport 8080 accept } }".to_string()),
            default_policy: FirewallPolicy::Drop,
        };

        let findings = build_firewall_findings(&status, None);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("Open firewall service detected"));
    }

    #[test]
    fn scope_matched_firewall_rule_is_info() {
        let status = FirewallStatus {
            backend: FirewallBackend::Nftables,
            rules_loaded: true,
            raw_output: Some("table inet filter { chain input { type filter hook input priority 0; tcp dport 8080 accept } }".to_string()),
            default_policy: FirewallPolicy::Drop,
        };

        let scope = ScopeFile {
            services: vec![ScopeService {
                name: "api-gateway".to_string(),
                protocol: "tcp".to_string(),
                host: "0.0.0.0".to_string(),
                port: 8080,
                exposed: true,
                description: Some("Main REST API gateway".to_string()),
            }],
        };

        let findings = build_firewall_findings(&status, Some(&scope));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(
            findings[0]
                .title
                .contains("Known scoped firewall service detected")
        );
    }

    #[test]
    fn unknown_backend_returns_high_severity() {
        let status = FirewallStatus {
            backend: FirewallBackend::Unknown,
            rules_loaded: false,
            raw_output: None,
            default_policy: FirewallPolicy::Unknown,
        };

        let findings = build_firewall_findings(&status, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
