use std::fs;
use std::path::Path;

use crate::finding::{Finding, Severity};

pub struct SshConfig {
    pub loaded: bool,
    pub permit_root_login: Option<String>,
    pub password_authentication: Option<String>,
    pub pubkey_authentication: Option<String>,
    pub protocol: Option<String>,
    pub permit_empty_passwords: Option<String>,
    pub allow_tcp_forwarding: Option<String>,
    pub x11_forwarding: Option<String>,
    pub challenge_response_authentication: Option<String>,
    pub host_key_files: Vec<String>,
}

impl SshConfig {
    pub fn is_empty(&self) -> bool {
        self.permit_root_login.is_none()
            && self.password_authentication.is_none()
            && self.pubkey_authentication.is_none()
            && self.protocol.is_none()
            && self.permit_empty_passwords.is_none()
            && self.allow_tcp_forwarding.is_none()
            && self.x11_forwarding.is_none()
            && self.challenge_response_authentication.is_none()
            && self.host_key_files.is_empty()
    }
}

pub fn load_ssh_config() -> SshConfig {
    let path = Path::new("/etc/ssh/sshd_config");
    let mut config = SshConfig {
        loaded: path.exists(),
        permit_root_login: None,
        password_authentication: None,
        pubkey_authentication: None,
        protocol: None,
        permit_empty_passwords: None,
        allow_tcp_forwarding: None,
        x11_forwarding: None,
        challenge_response_authentication: None,
        host_key_files: Vec::new(),
    };

    if !path.exists() {
        return config;
    }

    if let Ok(contents) = fs::read_to_string(path) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<_> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }

            match parts[0] {
                "PermitRootLogin" => config.permit_root_login = Some(parts[1..].join(" ")),
                "PasswordAuthentication" => {
                    config.password_authentication = Some(parts[1..].join(" "))
                }
                "PubkeyAuthentication" => config.pubkey_authentication = Some(parts[1..].join(" ")),
                "Protocol" => config.protocol = Some(parts[1..].join(" ")),
                "PermitEmptyPasswords" => {
                    config.permit_empty_passwords = Some(parts[1..].join(" "))
                }
                "AllowTcpForwarding" => config.allow_tcp_forwarding = Some(parts[1..].join(" ")),
                "X11Forwarding" => config.x11_forwarding = Some(parts[1..].join(" ")),
                "ChallengeResponseAuthentication" => {
                    config.challenge_response_authentication = Some(parts[1..].join(" "))
                }
                "HostKey" if parts.len() >= 2 => config.host_key_files.push(parts[1..].join(" ")),
                "HostKey" => {}
                _ => {}
            }
        }
    }

    config
}

fn check_root_login(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.permit_root_login
        && matches!(value.to_lowercase().as_str(), "yes" | "prohibit-password")
    {
        return Some(Finding {
            title: "SSH root login is enabled".to_string(),
            description: "The SSH daemon allows root login, which increases risk if credentials are compromised.".to_string(),
            risk: "An attacker with valid credentials or stolen keys can access the host as root.".to_string(),
            recommendation: "Set PermitRootLogin to no and use sudo-capable accounts for administrative access.".to_string(),
            severity: Severity::High,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_password_auth(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.password_authentication
        && value.to_lowercase() == "yes"
    {
        return Some(Finding {
            title: "SSH password authentication is enabled".to_string(),
            description: "Password-based SSH authentication is permitted.".to_string(),
            risk: "Passwords are easier to brute force or leak than properly managed keys."
                .to_string(),
            recommendation:
                "Disable PasswordAuthentication and use SSH keys or certificate authentication."
                    .to_string(),
            severity: Severity::Medium,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_pubkey_auth(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.pubkey_authentication
        && value.to_lowercase() == "no"
    {
        return Some(Finding {
            title: "SSH public-key authentication is disabled".to_string(),
            description: "SSH is not configured to allow public-key authentication.".to_string(),
            risk: "Users may rely on passwords even if other protections are enabled.".to_string(),
            recommendation: "Enable PubkeyAuthentication for stronger SSH authentication."
                .to_string(),
            severity: Severity::Low,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_protocol(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.protocol {
        let protocol = value.to_lowercase();
        if protocol.contains('1') && !protocol.contains('2') {
            return Some(Finding {
                title: "SSH protocol version 1 is enabled".to_string(),
                description: "SSH protocol version 1 is insecure and should not be accepted."
                    .to_string(),
                risk: "Protocol 1 is outdated and vulnerable to multiple cryptographic attacks."
                    .to_string(),
                recommendation: "Use Protocol 2 only and remove any Protocol 1 configuration."
                    .to_string(),
                severity: Severity::High,
                category: "SSH".to_string(),
            });
        }
    }
    None
}

fn check_empty_passwords_config(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.permit_empty_passwords
        && value.to_lowercase() == "yes"
    {
        return Some(Finding {
            title: "SSH allows empty passwords".to_string(),
            description: "PermitEmptyPasswords is enabled in SSH configuration.".to_string(),
            risk: "Empty passwords allow unauthorized access to accounts without any authentication.".to_string(),
            recommendation: "Set PermitEmptyPasswords to no and ensure all accounts have valid passwords or keys.".to_string(),
            severity: Severity::Critical,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_tcp_forwarding(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.allow_tcp_forwarding
        && value.to_lowercase() == "yes"
    {
        return Some(Finding {
            title: "SSH TCP forwarding is enabled".to_string(),
            description: "AllowTcpForwarding is enabled, which permits SSH tunnels.".to_string(),
            risk: "Open TCP forwarding can be abused to bypass network restrictions and exfiltrate traffic.".to_string(),
            recommendation: "Disable AllowTcpForwarding unless it is explicitly required for administration.".to_string(),
            severity: Severity::Low,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_x11_forwarding(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.x11_forwarding
        && value.to_lowercase() == "yes"
    {
        return Some(Finding {
            title: "SSH X11 forwarding is enabled".to_string(),
            description: "X11Forwarding is enabled in the SSH daemon.".to_string(),
            risk: "X11 forwarding may allow remote users to access or spoof graphical sessions."
                .to_string(),
            recommendation: "Disable X11Forwarding unless you explicitly need it.".to_string(),
            severity: Severity::Low,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_challenge_response(config: &SshConfig) -> Option<Finding> {
    if let Some(value) = &config.challenge_response_authentication
        && value.to_lowercase() == "yes"
    {
        return Some(Finding {
            title: "SSH challenge-response authentication is enabled".to_string(),
            description: "ChallengeResponseAuthentication is enabled.".to_string(),
            risk: "Challenge-response methods may permit legacy authentication paths that are harder to audit.".to_string(),
            recommendation: "Disable ChallengeResponseAuthentication unless required by your authentication provider.".to_string(),
            severity: Severity::Low,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_host_key_config(config: &SshConfig) -> Option<Finding> {
    if config.host_key_files.is_empty() {
        return Some(Finding {
            title: "SSH host keys are not configured".to_string(),
            description: "No HostKey directives were found in SSH configuration.".to_string(),
            risk: "SSH may fall back to defaults or fail to present a stable host key, reducing trustworthiness.".to_string(),
            recommendation: "Ensure HostKey directives are set for the expected host key files.".to_string(),
            severity: Severity::Low,
            category: "SSH".to_string(),
        });
    }
    None
}

fn check_empty_passwords_file() -> Option<Finding> {
    let shadow_path = Path::new("/etc/shadow");
    if !shadow_path.exists() {
        return Some(Finding {
            title: "SSH shadow file not readable".to_string(),
            description: "The /etc/shadow file could not be inspected for empty password hashes.".to_string(),
            risk: "Missing shadow file access may hide accounts with weak or empty passwords.".to_string(),
            recommendation: "Run ScopeGuard as a user with permission to read /etc/shadow or inspect the file manually.".to_string(),
            severity: Severity::Info,
            category: "SSH".to_string(),
        });
    }

    if let Ok(contents) = fs::read_to_string(shadow_path)
        && contents
            .lines()
            .any(|line| line.split(':').nth(1).is_some_and(|hash| hash.is_empty()))
    {
        return Some(Finding {
            title: "Empty password entry detected".to_string(),
            description: "At least one system account has an empty password hash in /etc/shadow."
                .to_string(),
            risk: "Accounts without a password hash may allow unauthorized access.".to_string(),
            recommendation:
                "Review accounts with empty password hashes and disable or protect them."
                    .to_string(),
            severity: Severity::Critical,
            category: "SSH".to_string(),
        });
    }

    None
}

pub fn run_ssh_audit() -> Vec<Finding> {
    let config = load_ssh_config();
    let mut findings = Vec::new();

    if let Some(finding) = check_root_login(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_password_auth(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_pubkey_auth(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_protocol(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_empty_passwords_config(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_tcp_forwarding(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_x11_forwarding(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_challenge_response(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_host_key_config(&config) {
        findings.push(finding);
    }
    if let Some(finding) = check_empty_passwords_file() {
        findings.push(finding);
    }

    if findings.is_empty() {
        if !config.loaded {
            findings.push(Finding {
                title: "SSH configuration not found".to_string(),
                description: "The SSH daemon configuration file /etc/ssh/sshd_config could not be located.".to_string(),
                risk: "SSH configuration could not be inspected, so potential weaknesses may be missed.".to_string(),
                recommendation: "Verify that sshd is installed and the configuration file is accessible to the scanner.".to_string(),
                severity: Severity::Info,
                category: "SSH".to_string(),
            });
        } else {
            findings.push(Finding {
                title: "SSH audit completed".to_string(),
                description:
                    "SSH configuration was inspected and no high-risk SSH settings were detected."
                        .to_string(),
                risk: "No SSH-specific issues were found by the current checks.".to_string(),
                recommendation:
                    "Review SSH configuration for additional hardening opportunities as needed."
                        .to_string(),
                severity: Severity::Info,
                category: "SSH".to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_audit_reports_protocol_one() {
        let config = SshConfig {
            loaded: true,
            permit_root_login: None,
            password_authentication: None,
            pubkey_authentication: None,
            protocol: Some("1".to_string()),
            permit_empty_passwords: None,
            allow_tcp_forwarding: None,
            x11_forwarding: None,
            challenge_response_authentication: None,
            host_key_files: vec!["/etc/ssh/ssh_host_rsa_key".to_string()],
        };

        assert!(check_protocol(&config).is_some());
    }

    #[test]
    fn ssh_audit_reports_empty_passwords_config() {
        let config = SshConfig {
            loaded: true,
            permit_root_login: None,
            password_authentication: None,
            pubkey_authentication: None,
            protocol: None,
            permit_empty_passwords: Some("yes".to_string()),
            allow_tcp_forwarding: None,
            x11_forwarding: None,
            challenge_response_authentication: None,
            host_key_files: vec!["/etc/ssh/ssh_host_rsa_key".to_string()],
        };

        assert!(check_empty_passwords_config(&config).is_some());
    }

    #[test]
    fn ssh_audit_reports_info_when_no_issues_found() {
        let config = SshConfig {
            loaded: true,
            permit_root_login: Some("no".to_string()),
            password_authentication: Some("no".to_string()),
            pubkey_authentication: Some("yes".to_string()),
            protocol: Some("2".to_string()),
            permit_empty_passwords: Some("no".to_string()),
            allow_tcp_forwarding: Some("no".to_string()),
            x11_forwarding: Some("no".to_string()),
            challenge_response_authentication: Some("no".to_string()),
            host_key_files: vec!["/etc/ssh/ssh_host_rsa_key".to_string()],
        };

        let mut findings = Vec::new();
        if let Some(finding) = check_root_login(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_password_auth(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_pubkey_auth(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_protocol(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_empty_passwords_config(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_tcp_forwarding(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_x11_forwarding(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_challenge_response(&config) {
            findings.push(finding);
        }
        if let Some(finding) = check_host_key_config(&config) {
            findings.push(finding);
        }

        assert!(findings.is_empty());
    }
}
