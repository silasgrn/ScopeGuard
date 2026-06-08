use crate::finding::Finding;
use serde_json::{Value, json};

pub fn render_json(findings: &[Finding]) -> Value {
    json!({
        "findings": findings.iter().map(|finding| {
            json!({
                "title": finding.title,
                "description": finding.description,
                "risk": finding.risk,
                "recommendation": finding.recommendation,
                "severity": finding.severity.as_str(),
                "category": finding.category,
            })
        }).collect::<Vec<_>>()
    })
}

pub fn render_human(findings: &[Finding]) -> String {
    let mut output = String::new();
    output.push_str("ScopeGuard Findings\n====================\n");

    for finding in findings {
        output.push_str(&format!(
            "\n- [{}] {} ({})\n  {}\n  Recommendation: {}\n",
            finding.severity.as_str(),
            finding.title,
            finding.category,
            finding.description,
            finding.recommendation,
        ));
    }

    if findings.is_empty() {
        output.push_str("\nNo findings detected.\n");
    }

    output
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn render_html(findings: &[Finding]) -> String {
    let items: String = findings
        .iter()
        .map(|finding| {
            format!(
                "<section>\n  <h2>{}</h2>\n  <p><strong>Severity:</strong> {}</p>\n  <p><strong>Category:</strong> {}</p>\n  <p>{}</p>\n  <p><strong>Risk:</strong> {}</p>\n  <p><strong>Recommendation:</strong> {}</p>\n</section>\n",
                escape_html(&finding.title),
                escape_html(finding.severity.as_str()),
                escape_html(&finding.category),
                escape_html(&finding.description),
                escape_html(&finding.risk),
                escape_html(&finding.recommendation),
            )
        })
        .collect();

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\">\n  <title>ScopeGuard Report</title>\n</head>\n<body>\n  <h1>ScopeGuard Report</h1>\n  {}\n</body>\n</html>\n",
        items
    )
}
