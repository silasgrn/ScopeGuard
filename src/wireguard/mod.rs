use std::process::Command;

use crate::finding::{Finding, Severity};

pub struct WireGuardPeer {
    pub public_key: String,
    pub latest_handshake: u64,
    pub endpoint: Option<String>,
}

fn load_wireguard_peers() -> Result<Vec<WireGuardPeer>, String> {
    let output = Command::new("wg")
        .arg("show")
        .arg("all")
        .arg("dump")
        .output()
        .map_err(|_| "WireGuard command unavailable".to_string())?;

    if !output.status.success() {
        return Err("WireGuard command failed".to_string());
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let peers = body
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            let public_key = fields[1].to_string();
            let latest_handshake = fields[5].parse::<u64>().unwrap_or(0);
            let endpoint = if fields[4] != "-" {
                Some(fields[4].to_string())
            } else {
                None
            };

            Some(WireGuardPeer {
                public_key,
                latest_handshake,
                endpoint,
            })
        })
        .collect();

    Ok(peers)
}

pub fn run_wireguard_audit() -> Vec<Finding> {
    let peers = match load_wireguard_peers() {
        Ok(peers) => peers,
        Err(_) => {
            return vec![Finding {
                title: "WireGuard audit unavailable".to_string(),
                description:
                    "The WireGuard toolchain is unavailable or peer state could not be read."
                        .to_string(),
                risk: "WireGuard activity cannot be audited without access to the wg command."
                    .to_string(),
                recommendation:
                    "Install WireGuard tools and rerun the scan to inspect peer configurations."
                        .to_string(),
                severity: Severity::Info,
                category: "WireGuard".to_string(),
            }];
        }
    };

    let mut findings = Vec::new();

    for peer in peers.iter() {
        if peer.latest_handshake == 0 {
            findings.push(Finding {
                title: format!("WireGuard peer appears inactive: {}", peer.public_key),
                description: format!("Peer {} has no recent handshake recorded.", peer.public_key),
                risk:
                    "An inactive WireGuard peer may represent stale or unused access credentials."
                        .to_string(),
                recommendation: "Remove or rotate unused WireGuard peers to reduce attack surface."
                    .to_string(),
                severity: Severity::Low,
                category: "WireGuard".to_string(),
            });
        }
    }

    if findings.is_empty() {
        if peers.is_empty() {
            findings.push(Finding {
                title: "No WireGuard peers detected".to_string(),
                description: "No WireGuard peers were found during the peer state inspection."
                    .to_string(),
                risk: "No WireGuard peers were discovered, so VPN peer risks are not present."
                    .to_string(),
                recommendation:
                    "Add WireGuard peers or verify configuration before rerunning the audit."
                        .to_string(),
                severity: Severity::Info,
                category: "WireGuard".to_string(),
            });
        } else {
            findings.push(Finding {
                title: "WireGuard audit completed".to_string(),
                description: "WireGuard peers were examined and no inactive peers were detected."
                    .to_string(),
                risk: "All discovered WireGuard peers have recent handshake activity.".to_string(),
                recommendation:
                    "Continue monitoring peer health and remove unused peers when appropriate."
                        .to_string(),
                severity: Severity::Info,
                category: "WireGuard".to_string(),
            });
        }
    }

    findings
}
