use crate::finding::{Finding, Severity};
use std::process::Command;

fn run_command_with_sudo_fallback(cmd: &str, args: &[&str]) -> Option<String> {
    if let Ok(output) = Command::new(cmd).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    if let Ok(output) = Command::new("sudo").args(["-n", cmd]).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    if let Ok(output) = Command::new("sudo").arg(cmd).args(args).output()
        && output.status.success()
    {
        return Some(String::from_utf8_lossy(&output.stdout).into_owned());
    }

    None
}

pub struct AttackSurfaceNode {
    pub node_type: String,
    pub name: String,
    pub description: String,
}

fn parse_listening_nodes(output: &str) -> Vec<AttackSurfaceNode> {
    output
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            if columns.len() < 5 {
                return None;
            }

            let proto = columns[0].to_string();
            let local_address = columns[4];
            let (address, port) = local_address
                .rsplit_once(':')
                .unwrap_or((local_address, "0"));
            let exposed = address == "0.0.0.0" || address == "::" || address == ":::";

            if !exposed {
                return None;
            }

            Some(AttackSurfaceNode {
                node_type: "Service".to_string(),
                name: format!("{}:{}", proto, port),
                description: format!(
                    "{} service exposed on {}:{}",
                    proto.to_uppercase(),
                    address,
                    port
                ),
            })
        })
        .collect()
}

fn discover_attack_surface_nodes() -> Vec<AttackSurfaceNode> {
    let mut nodes = vec![AttackSurfaceNode {
        node_type: "Host".to_string(),
        name: "scopeguard-host".to_string(),
        description: "Local host node representing the scanned machine.".to_string(),
    }];

    if let Some(content) = run_command_with_sudo_fallback("ss", &["-tuln"]) {
        nodes.extend(parse_listening_nodes(&content));
    }

    nodes
}

pub fn run_attack_surface_audit() -> Vec<Finding> {
    let nodes = discover_attack_surface_nodes();

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
