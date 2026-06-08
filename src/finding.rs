#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub risk: String,
    pub recommendation: String,
    pub severity: Severity,
    pub category: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }
}
