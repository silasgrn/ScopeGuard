use std::process::Command;

use crate::finding::{Finding, Severity};
use serde::Deserialize;

pub struct ContainerStatus {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    pub host_network: bool,
    pub host_mount: bool,
}

#[derive(Debug, Deserialize)]
struct ContainerPsEntry {
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "ID")]
    id: String,
}

#[derive(Debug, Deserialize)]
struct HostConfig {
    #[serde(rename = "Privileged")]
    privileged: bool,
    #[serde(rename = "NetworkMode")]
    network_mode: String,
    #[serde(rename = "Mounts")]
    mounts: Vec<MountEntry>,
}

#[derive(Debug, Deserialize)]
struct MountEntry {
    #[serde(rename = "Source")]
    source: Option<String>,
}

fn detect_container_runtime() -> Option<&'static str> {
    if Command::new("docker").arg("--version").output().is_ok() {
        Some("docker")
    } else if Command::new("podman").arg("--version").output().is_ok() {
        Some("podman")
    } else {
        None
    }
}

fn inspect_host_config(engine: &str, id: &str) -> Option<HostConfig> {
    let output = Command::new(engine)
        .args(["inspect", "--format", "{{json .HostConfig}}", id])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    serde_json::from_slice(&output.stdout).ok()
}

fn list_containers() -> Vec<ContainerStatus> {
    let engine = match detect_container_runtime() {
        Some(engine) => engine,
        None => return Vec::new(),
    };

    let output = Command::new(engine)
        .args(["ps", "-a", "--format", "{{json .}}"])
        .output();

    let output = match output {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };

    let body = String::from_utf8_lossy(&output.stdout);
    body.lines()
        .filter_map(|line| serde_json::from_str::<ContainerPsEntry>(line).ok())
        .map(|entry| {
            let host_config = inspect_host_config(engine, &entry.id);
            let privileged = host_config.as_ref().map_or(false, |config| config.privileged);
            let host_network = host_config
                .as_ref()
                .map_or(false, |config| config.network_mode == "host");
            let host_mount = host_config.as_ref().map_or(false, |config| {
                config.mounts.iter().any(|mount| mount.source.is_some())
            });

            ContainerStatus {
                name: entry.names,
                image: entry.image,
                privileged,
                host_network,
                host_mount,
            }
        })
        .collect()
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
                description: format!(
                    "Container {} shares the host network namespace.",
                    container.name
                ),
                risk: "Host network mode exposes container services on all host interfaces.".to_string(),
                recommendation: "Use bridge or overlay networking instead of host network mode.".to_string(),
                severity: Severity::Medium,
                category: "Container Security".to_string(),
            });
        }

        if container.host_mount {
            findings.push(Finding {
                title: format!("Container has host mount: {}", container.name),
                description: format!(
                    "Container {} mounts host file system paths into the container.",
                    container.name
                ),
                risk: "Host mounts may expose host files and secrets to container processes.".to_string(),
                recommendation: "Limit host mounts to only the paths required by the workload.".to_string(),
                severity: Severity::Medium,
                category: "Container Security".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "Container audit completed".to_string(),
            description: "No insecure container runtime settings were detected.".to_string(),
            risk: "No privileged host mounts or host network containers were identified.".to_string(),
            recommendation: "Monitor container runtime security and extend coverage to additional runtimes.".to_string(),
            severity: Severity::Info,
            category: "Container Security".to_string(),
        });
    }

    findings
}

pub fn run_container_audit() -> Vec<Finding> {
    let containers = list_containers();

    if containers.is_empty() {
        if detect_container_runtime().is_some() {
            return vec![Finding {
                title: "No containers detected".to_string(),
                description: "The container runtime was detected, but no containers are currently present.".to_string(),
                risk: "No containers were found, so container runtime security issues cannot be evaluated.".to_string(),
                recommendation: "Run containers or verify the container runtime before re-running the audit.".to_string(),
                severity: Severity::Info,
                category: "Container Security".to_string(),
            }];
        }

        return vec![Finding {
            title: "Container runtime unavailable".to_string(),
            description: "Neither Docker nor Podman could be accessed to inspect running containers.".to_string(),
            risk: "Container runtime inspection is unavailable, so container-related risks may be missed.".to_string(),
            recommendation: "Install Docker or Podman and grant appropriate access to the scanner.".to_string(),
            severity: Severity::Info,
            category: "Container Security".to_string(),
        }];
    }

    build_container_findings(&containers)
}
