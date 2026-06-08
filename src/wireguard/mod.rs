use crate::finding::{Finding, Severity};

pub struct WireGuardPeer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub latest_handshake: Option<String>,
    pub endpoint: Option<String>,
}

fn load_wireguard_peers() -> Vec<WireGuardPeer> {
    vec![
        WireGuardPeer {
            public_key: "abc123...".to_string(),
            allowed_ips: vec!["10.0.0.2/32".to_string()],
            latest_handshake: Some("2026-06-07 18:34:00".to_string()),
            endpoint: Some("vpn.example.local:51820".to_string()),
        },
        WireGuardPeer {
            public_key: "def456...".to_string(),
            allowed_ips: vec!["10.0.0.3/32".to_string()],
            latest_handshake: None,
            endpoint: Some("vpn.example.local:51820".to_string()),
        },
    ]
}

pub fn run_wireguard_audit() -> Vec<Finding> {
    let peers = load_wireguard_peers();
    let mut findings = Vec::new();

    for peer in peers {
        if peer.latest_handshake.is_none() {
            findings.push(Finding {
                title: format!("WireGuard peer appears inactive: {}", peer.public_key),
                description: format!("Peer {} has no recent handshake recorded.", peer.public_key),
                risk: "An inactive WireGuard peer may represent stale or unused access credentials.".to_string(),
                recommendation: "Remove or rotate unused WireGuard peers to reduce attack surface.".to_string(),
                severity: Severity::Low,
                category: "WireGuard".to_string(),
            });
        }
    }

    if findings.is_empty() {
        findings.push(Finding {
            title: "WireGuard audit placeholder".to_string(),
            description: "WireGuard peers were inspected and no stale peer placeholders were detected.".to_string(),
            risk: "WireGuard audit is active but requires real peer state collection.".to_string(),
            recommendation: "Integrate actual WireGuard configuration parsing and handshake verification.".to_string(),
            severity: Severity::Info,
            category: "WireGuard".to_string(),
        });
    }

    findings
}
