use std::fs;
use std::path::Path;

use crate::finding::{Finding, Severity};

pub struct SshConfig {
    pub permit_root_login: Option<String>,
    pub password_authentication: Option<String>,
    pub pubkey_authentication: Option<String>,
}

impl SshConfig {
    pub fn is_empty(&self) -> bool {
        self.permit_root_login.is_none()
            && self.password_authentication.is_none()
            && self.pubkey_authentication.is_none()
    }
}

pub fn load_ssh_config() -> SshConfig {
    let path = Path::new("/etc/ssh/sshd_config");
    let mut config = SshConfig {
        permit_root_login: None,
        password_authentication: None,
        pubkey_authentication: None,
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
            if parts.len() >= 2 {
                match parts[0] {
                    "PermitRootLogin" => config.permit_root_login = Some(parts[1..].join(" ")),
                    "PasswordAuthentication" => {
                        config.password_authentication = Some(parts[1..].join(" "))
                    }
                    "PubkeyAuthentication" => {
                        config.pubkey_authentication = Some(parts[1..].join(" "))
                    }
                    _ => {}
                }
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
            category: "Host Security".to_string(),
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
            category: "Host Security".to_string(),
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
            category: "Host Security".to_string(),
        });
    }
    None
}

fn check_empty_passwords() -> Option<Finding> {
    let shadow_path = Path::new("/etc/shadow");
    if !shadow_path.exists() {
        return Some(Finding {
            title: "SSH shadow file not readable".to_string(),
            description: "The /etc/shadow file could not be inspected for empty password hashes.".to_string(),
            risk: "Missing shadow file access may hide accounts with weak or empty passwords.".to_string(),
            recommendation: "Run ScopeGuard as a user with permission to read /etc/shadow or inspect the file manually.".to_string(),
            severity: Severity::Info,
            category: "Host Security".to_string(),
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
            category: "Host Security".to_string(),
        });
    }

    None
}

pub fn run_host_audit() -> Vec<Finding> {
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
    if let Some(finding) = check_empty_passwords() {
        findings.push(finding);
    }

    if findings.is_empty() && config.is_empty() {
        findings.push(Finding {
            title: "SSH audit loaded default placeholder".to_string(),
            description: "SSH audit is configured and waiting to inspect real SSH configuration values.".to_string(),
            risk: "No SSH-specific findings were generated because no relevant configuration items were detected.".to_string(),
            recommendation: "Add SSH daemon configuration checks and run the scanner again.".to_string(),
            severity: Severity::Info,
            category: "Host Security".to_string(),
        });
    }

    findings
}
