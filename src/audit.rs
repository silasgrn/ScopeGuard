use crate::finding::Finding;

pub fn run_all_audits() -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(crate::host::run_host_audit());
    findings.extend(crate::network::run_network_audit());
    findings.extend(crate::firewall::run_firewall_audit());
    findings.extend(crate::docker::run_container_audit());
    findings.extend(crate::vm::run_virtualization_audit());
    findings.extend(crate::services::run_services_audit());
    findings.extend(crate::wireguard::run_wireguard_audit());
    findings.extend(crate::attack_surface::run_attack_surface_audit());

    findings
}
