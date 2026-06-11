use super::backend::detect_firewall;
use super::findings::build_firewall_findings;
use crate::scope::ScopeFile;

pub fn run_firewall_audit(scope: Option<&ScopeFile>) -> Vec<crate::finding::Finding> {
    let status = detect_firewall();
    build_firewall_findings(&status, scope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::backend::{FirewallBackend, FirewallPolicy, FirewallStatus};

    #[test]
    fn run_firewall_audit_returns_findings() {
        let status = FirewallStatus {
            backend: FirewallBackend::Unknown,
            rules_loaded: false,
            raw_output: None,
            default_policy: FirewallPolicy::Unknown,
        };

        let findings = build_firewall_findings(&status, None);
        assert_eq!(findings.len(), 1);
    }
}
