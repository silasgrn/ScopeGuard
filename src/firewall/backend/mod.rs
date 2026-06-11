use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    Ufw,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FirewallPolicy {
    Accept,
    Drop,
    Reject,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct FirewallRule {
    pub protocol: String,
    pub port: u16,
    pub destination: String,
    pub action: String,
}

pub struct FirewallStatus {
    pub backend: FirewallBackend,
    pub rules_loaded: bool,
    pub raw_output: Option<String>,
    pub default_policy: FirewallPolicy,
}

impl FirewallStatus {
    pub fn is_backend_available(&self) -> bool {
        !matches!(self.backend, FirewallBackend::Unknown)
    }

    pub fn has_permissive_default_policy(&self) -> bool {
        matches!(self.default_policy, FirewallPolicy::Accept)
    }
}

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

fn parse_nft_default_policy(output: &str) -> FirewallPolicy {
    output
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.contains("policy accept") {
                Some(FirewallPolicy::Accept)
            } else if lower.contains("policy drop") {
                Some(FirewallPolicy::Drop)
            } else if lower.contains("policy reject") {
                Some(FirewallPolicy::Reject)
            } else {
                None
            }
        })
        .unwrap_or(FirewallPolicy::Unknown)
}

fn parse_iptables_default_policy(output: &str) -> FirewallPolicy {
    output
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("chain input") {
                lower
                    .split('(')
                    .nth(1)
                    .and_then(|part| part.split(')').next())
                    .and_then(|policy| policy.split_whitespace().nth(1))
                    .map(|policy| match policy {
                        "accept" => FirewallPolicy::Accept,
                        "drop" => FirewallPolicy::Drop,
                        "reject" => FirewallPolicy::Reject,
                        _ => FirewallPolicy::Unknown,
                    })
            } else {
                None
            }
        })
        .unwrap_or(FirewallPolicy::Unknown)
}

fn parse_ufw_default_policy(output: &str) -> FirewallPolicy {
    output
        .lines()
        .find_map(|line| {
            let lower = line.trim().to_lowercase();
            if lower.starts_with("default:") {
                lower
                    .trim_start_matches("default:")
                    .trim()
                    .split_whitespace()
                    .next()
                    .map(|policy| match policy {
                        "allow" | "accept" => FirewallPolicy::Accept,
                        "deny" => FirewallPolicy::Drop,
                        "reject" => FirewallPolicy::Reject,
                        _ => FirewallPolicy::Unknown,
                    })
            } else {
                None
            }
        })
        .unwrap_or(FirewallPolicy::Unknown)
}

pub fn detect_firewall() -> FirewallStatus {
    if let Some(output) = run_command_with_sudo_fallback("nft", &["list", "ruleset"]) {
        let default_policy = parse_nft_default_policy(&output);
        return FirewallStatus {
            backend: FirewallBackend::Nftables,
            rules_loaded: true,
            raw_output: Some(output),
            default_policy,
        };
    }

    if let Some(output) = run_command_with_sudo_fallback("iptables", &["-L", "-n", "-v"]) {
        let default_policy = parse_iptables_default_policy(&output);
        return FirewallStatus {
            backend: FirewallBackend::Iptables,
            rules_loaded: true,
            raw_output: Some(output),
            default_policy,
        };
    }

    if let Some(output) = run_command_with_sudo_fallback("ufw", &["status", "verbose"]) {
        let active = output.to_lowercase().contains("status: active");
        let default_policy = parse_ufw_default_policy(&output);
        return FirewallStatus {
            backend: FirewallBackend::Ufw,
            rules_loaded: active,
            raw_output: Some(output),
            default_policy,
        };
    }

    FirewallStatus {
        backend: FirewallBackend::Unknown,
        rules_loaded: false,
        raw_output: None,
        default_policy: FirewallPolicy::Unknown,
    }
}

fn parse_port(token: &str) -> Option<u16> {
    let digits: String = token.chars().filter(|c| c.is_ascii_digit()).collect();
    digits.parse::<u16>().ok()
}

fn parse_destination(line: &str) -> String {
    let lower = line.to_lowercase();
    let tokens: Vec<_> = lower.split_whitespace().collect();

    for i in 0..tokens.len() {
        if tokens[i] == "ip" && i + 2 < tokens.len() && tokens[i + 1] == "daddr" {
            return tokens[i + 2].trim_end_matches(',').to_string();
        }

        if tokens[i] == "ipv6" && i + 2 < tokens.len() && tokens[i + 1] == "daddr" {
            return tokens[i + 2].trim_end_matches(',').to_string();
        }
    }

    if let Some(dpt) = lower
        .split_whitespace()
        .find(|token| token.starts_with("dpt:"))
    {
        return dpt.trim_start_matches("dpt:").to_string();
    }

    "0.0.0.0/0".to_string()
}

fn parse_nft_rules(output: &str) -> Vec<FirewallRule> {
    output
        .lines()
        .filter_map(|line| {
            let lower = line.to_lowercase();
            if !lower.contains("accept") {
                return None;
            }

            let protocol = if lower.contains("tcp") {
                "tcp"
            } else if lower.contains("udp") {
                "udp"
            } else {
                return None;
            };

            let tokens: Vec<_> = lower.split_whitespace().collect();
            let port = tokens.iter().enumerate().find_map(|(index, token)| {
                if *token == "dport" {
                    tokens.get(index + 1).and_then(|next| parse_port(next))
                } else if token.starts_with("dport") {
                    parse_port(token)
                } else {
                    None
                }
            });

            let port = port?;
            Some(FirewallRule {
                protocol: protocol.to_string(),
                port,
                destination: parse_destination(line),
                action: "accept".to_string(),
            })
        })
        .collect()
}

fn parse_iptables_rules(output: &str) -> Vec<FirewallRule> {
    output
        .lines()
        .filter_map(|line| {
            let lower = line.to_lowercase();
            if !lower.contains("accept") || !lower.contains("dpt:") {
                return None;
            }

            let protocol = if lower.contains("tcp") {
                "tcp"
            } else if lower.contains("udp") {
                "udp"
            } else {
                "tcp"
            };

            let port = lower
                .split_whitespace()
                .find_map(|token| token.strip_prefix("dpt:").and_then(parse_port));

            let port = port?;
            let destination = line
                .split_whitespace()
                .find(|token| token.contains("/0"))
                .map(|token| token.to_string())
                .unwrap_or_else(|| "0.0.0.0/0".to_string());

            Some(FirewallRule {
                protocol: protocol.to_string(),
                port,
                destination,
                action: "accept".to_string(),
            })
        })
        .collect()
}

fn parse_ufw_rules(output: &str) -> Vec<FirewallRule> {
    output
        .lines()
        .filter_map(|line| {
            let lower = line.to_lowercase();
            if !lower.contains("allow") {
                return None;
            }

            let tokens: Vec<_> = line.split_whitespace().collect();
            if tokens.is_empty() {
                return None;
            }

            let port_proto = tokens[0];
            let (protocol, port) = if let Some((port, proto)) = port_proto.split_once('/') {
                (proto, parse_port(port))
            } else {
                ("tcp", parse_port(port_proto))
            };

            let port = port?;
            Some(FirewallRule {
                protocol: protocol.to_string(),
                port,
                destination: "0.0.0.0/0".to_string(),
                action: "allow".to_string(),
            })
        })
        .collect()
}

pub fn parse_firewall_rules(status: &FirewallStatus) -> Vec<FirewallRule> {
    let body = status.raw_output.as_deref().unwrap_or("");
    match status.backend {
        FirewallBackend::Nftables => parse_nft_rules(body),
        FirewallBackend::Iptables => parse_iptables_rules(body),
        FirewallBackend::Ufw => parse_ufw_rules(body),
        FirewallBackend::Unknown => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firewall_status_unknown_is_not_available() {
        let status = FirewallStatus {
            backend: FirewallBackend::Unknown,
            rules_loaded: false,
            raw_output: None,
            default_policy: FirewallPolicy::Unknown,
        };

        assert!(!status.is_backend_available());
        assert_eq!(status.backend, FirewallBackend::Unknown);
    }

    #[test]
    fn parse_nft_default_policy_detects_drop() {
        let output = "table inet filter {\n chain input { type filter hook input priority 0; policy drop; } }";
        assert_eq!(parse_nft_default_policy(output), FirewallPolicy::Drop);
    }

    #[test]
    fn parse_iptables_default_policy_detects_accept() {
        let output = "Chain INPUT (policy ACCEPT)";
        assert_eq!(parse_iptables_default_policy(output), FirewallPolicy::Accept);
    }

    #[test]
    fn parse_ufw_default_policy_detects_deny() {
        let output = "Status: active\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n";
        assert_eq!(parse_ufw_default_policy(output), FirewallPolicy::Drop);
    }

    #[test]
    fn parse_nft_rules_extracts_tcp_ports() {
        let output = "table inet filter {\n chain input { type filter hook input priority 0; policy drop; tcp dport 8080 accept }\n}";
        let rules = parse_nft_rules(output);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].port, 8080);
        assert_eq!(rules[0].protocol, "tcp");
    }

    #[test]
    fn parse_iptables_rules_extracts_tcp_ports() {
        let output = "ACCEPT     tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:22";
        let rules = parse_iptables_rules(output);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].port, 22);
        assert_eq!(rules[0].protocol, "tcp");
    }

    #[test]
    fn parse_ufw_rules_extracts_udp_ports() {
        let output = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n9001/udp                   ALLOW       Anywhere                  \n9001/tcp                   ALLOW       Anywhere                  \n";
        let rules = parse_ufw_rules(output);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].port, 9001);
        assert_eq!(rules[0].protocol, "udp");
        assert_eq!(rules[1].protocol, "tcp");
    }
}
