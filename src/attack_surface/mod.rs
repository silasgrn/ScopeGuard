use crate::finding::{Finding, Severity};

pub struct AttackSurfaceNode {
    pub node_type: String,
    pub name: String,
    pub description: String,
}

pub fn run_attack_surface_audit() -> Vec<Finding> {
    let nodes = vec![
        AttackSurfaceNode {
            node_type: "Host".to_string(),
            name: "scopeguard-host".to_string(),
            description: "Local host node representing the scanned machine.".to_string(),
        },
        AttackSurfaceNode {
            node_type: "Service".to_string(),
            name: "nginx".to_string(),
            description: "Web service exposed to the network.".to_string(),
        },
    ];

    if nodes.is_empty() {
        return vec![Finding {
            title: "Attack surface audit placeholder".to_string(),
            description: "Attack surface modeling is initialized and waiting for discovered nodes."
                .to_string(),
            risk: "No nodes are yet available for attack surface analysis.".to_string(),
            recommendation: "Add actual discovery of hosts, containers, services, and VPN peers."
                .to_string(),
            severity: Severity::Info,
            category: "Attack Surface".to_string(),
        }];
    }

    nodes
        .into_iter()
        .map(|node| Finding {
            title: format!("Attack surface node discovered: {}", node.name),
            description: format!("{} node discovered: {}.", node.node_type, node.description),
            risk:
                "Discovered nodes may expose services or routes that increase the attack surface."
                    .to_string(),
            recommendation:
                "Map the relationships between discovered nodes and review exposed dependencies."
                    .to_string(),
            severity: Severity::Info,
            category: "Attack Surface".to_string(),
        })
        .collect()
}
