use crate::finding::{Finding, Severity};

pub struct VirtualMachineInfo {
    pub name: String,
    pub hypervisor: String,
    pub network_mode: String,
    pub firewall_enabled: bool,
}

fn discover_virtual_machines() -> Vec<VirtualMachineInfo> {
    vec![
        VirtualMachineInfo {
            name: "prod-db".to_string(),
            hypervisor: "KVM/QEMU".to_string(),
            network_mode: "bridge".to_string(),
            firewall_enabled: false,
        },
        VirtualMachineInfo {
            name: "dev-workstation".to_string(),
            hypervisor: "Proxmox".to_string(),
            network_mode: "nat".to_string(),
            firewall_enabled: true,
        },
    ]
}

pub fn run_virtualization_audit() -> Vec<Finding> {
    let vms = discover_virtual_machines();
    let mut findings = Vec::new();

    for vm in vms {
        if vm.network_mode == "bridge" {
            findings.push(Finding {
                title: format!("Virtual machine uses bridged networking: {}", vm.name),
                description: format!("{} is attached to bridged networking, which may expose it directly on the LAN.", vm.name),
                risk: "Bridged VMs can be reached from local network attackers if not isolated.".to_string(),
                recommendation: "Review VM network settings and apply firewall rules or VLAN segmentation.".to_string(),
                severity: Severity::Medium,
                category: "Virtualization Security".to_string(),
            });
        }

        if !vm.firewall_enabled {
            findings.push(Finding {
                title: format!("Virtual machine firewall not enabled: {}", vm.name),
                description: format!(
                    "{} does not appear to have a guest firewall enabled.",
                    vm.name
                ),
                risk: "A VM without an internal firewall is more vulnerable to exposed services."
                    .to_string(),
                recommendation:
                    "Enable a firewall inside the guest or restrict its network exposure."
                        .to_string(),
                severity: Severity::Low,
                category: "Virtualization Security".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "Virtualization audit placeholder".to_string(),
            description: "No risky virtualization patterns were detected by the placeholder VM discovery.".to_string(),
            risk: "Virtualization checks are available but not yet complete for every hypervisor.".to_string(),
            recommendation: "Extend VM discovery to include actual QEMU, Proxmox, and containerized VM platforms.".to_string(),
            severity: Severity::Info,
            category: "Virtualization Security".to_string(),
        });
    }

    findings
}
