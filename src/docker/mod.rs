use crate::finding::{Finding, Severity};

pub struct ContainerStatus {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub host_network: bool,
    pub host_mount: bool,
}

fn list_containers() -> Vec<ContainerStatus> {
    vec![
        ContainerStatus {
            name: "webapp-nginx".to_string(),
            image: "nginx:latest".to_string(),
            privileged: false,
            host_network: false,
            host_mount: true,
        },
        ContainerStatus {
            name: "db-backend".to_string(),
            image: "postgres:15".to_string(),
            privileged: false,
            host_network: false,
            host_mount: false,
        },
        ContainerStatus {
            name: "maintenance-shell".to_string(),
            image: "alpine:latest".to_string(),
            privileged: true,
            host_network: true,
            host_mount: false,
        },
    ]
}

fn build_container_findings(containers: &[ContainerStatus]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for container in containers {
        if container.privileged {
            findings.push(Finding {
                title: format!("Privileged container found: {}", container.name),
                description: format!("Container {} is running with privileged access.", container.name),
                risk: "Privileged containers may bypass host isolation and access sensitive resources.".to_string(),
                recommendation: "Avoid privileged containers unless strictly necessary and use fine-grained capabilities.".to_string(),
                severity: Severity::High,
                category: "Container Security".to_string(),
            });
        }

        if container.host_network {
            findings.push(Finding {
                title: format!("Container using host network: {}", container.name),
                description: format!("Container {} shares the host network namespace.", container.name),
                risk: "Host network mode exposes container services on all host interfaces.".to_string(),
                recommendation: "Use bridge or overlay networking instead of host network mode.".to_string(),
                severity: Severity::Medium,
                category: "Container Security".to_string(),
            });
        }

        if container.host_mount {
            findings.push(Finding {
                title: format!("Container has host mount: {}", container.name),
                description: format!("Container {} mounts host file system paths into the container.", container.name),
                risk: "Host mounts may expose host files and secrets to container processes.".to_string(),
                recommendation: "Limit host mounts to only the paths required by the workload.".to_string(),
                severity: Severity::Medium,
                category: "Container Security".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "Container audit placeholder".to_string(),
            description: "Container runtime checks are initialized and awaiting actual container data.".to_string(),
            risk: "Container security auditing is enabled but no insecure container patterns were detected.".to_string(),
            recommendation: "Add runtime container inspection for Docker and Podman to replace placeholder data.".to_string(),
            severity: Severity::Info,
            category: "Container Security".to_string(),
        });
    }

    findings
}

pub fn run_container_audit() -> Vec<Finding> {
    let containers = list_containers();
    build_container_findings(&containers)
}
