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
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    sorted.sort_by_key(|finding| match finding.severity {
        crate::finding::Severity::Critical => 0,
        crate::finding::Severity::High => 1,
        crate::finding::Severity::Medium => 2,
        crate::finding::Severity::Low => 3,
        crate::finding::Severity::Info => 4,
    });

    let total = sorted.len();
    let critical = sorted
        .iter()
        .filter(|f| f.severity == crate::finding::Severity::Critical)
        .count();
    let high = sorted
        .iter()
        .filter(|f| f.severity == crate::finding::Severity::High)
        .count();
    let medium = sorted
        .iter()
        .filter(|f| f.severity == crate::finding::Severity::Medium)
        .count();
    let low = sorted
        .iter()
        .filter(|f| f.severity == crate::finding::Severity::Low)
        .count();
    let info = sorted
        .iter()
        .filter(|f| f.severity == crate::finding::Severity::Info)
        .count();

    let items: String = sorted
        .iter()
        .map(|finding| {
            let severity = escape_html(finding.severity.as_str());
            let title = escape_html(&finding.title);
            let category = escape_html(&finding.category);
            let description = escape_html(&finding.description);
            let risk = escape_html(&finding.risk);
            let recommendation = escape_html(&finding.recommendation);
            let badge_class = match finding.severity {
                crate::finding::Severity::Critical => "critical",
                crate::finding::Severity::High => "high",
                crate::finding::Severity::Medium => "medium",
                crate::finding::Severity::Low => "low",
                crate::finding::Severity::Info => "info",
            };

            format!(
                "<details class=\"finding\" data-severity=\"{severity}\" data-category=\"{category}\" data-title=\"{title}\">\n  <summary>\n    <div class=\"finding-summary\">\n      <h2>{title}</h2>\n      <div class=\"finding-meta\">\n        <span class=\"badge {badge_class}\">{severity}</span>\n        <span>{category}</span>\n      </div>\n    </div>\n  </summary>\n  <div class=\"finding-body\">\n    <p>{description}</p>\n    <p><span class=\"field-label\">Risk:</span> {risk}</p>\n    <p><span class=\"field-label\">Recommendation:</span> {recommendation}</p>\n  </div>\n</details>\n",
                severity = severity,
                title = title,
                category = category,
                description = description,
                risk = risk,
                recommendation = recommendation,
                badge_class = badge_class,
            )
        })
        .collect();

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"UTF-8\">\n  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n  <title>ScopeGuard Report</title>\n  <style>\n    :root {{\n      color-scheme: light;\n      font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;\n      background: #eff3f7;\n      color: #1f2937;\n    }}\n    * {{ box-sizing: border-box; }}\n    body {{ margin: 0; padding: 0; min-height: 100vh; background: #f8fafc; }}\n    header {{ padding: 2rem 1.5rem 1rem; background: linear-gradient(135deg, #0f172a, #1e293b); color: #f8fafc; text-align: center; }}\n    header h1 {{ margin: 0; font-size: clamp(2rem, 2.8vw, 3rem); letter-spacing: -0.04em; }}\n    header p {{ margin: 0.75rem auto 0; max-width: 38rem; color: #cbd5e1; line-height: 1.8; }}\n    main {{ max-width: 1024px; margin: 0 auto; padding: 1.5rem; }}\n    .toolbar {{ display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }}\n    .toolbar input {{ flex: 1 1 260px; min-width: 220px; padding: 0.95rem 1rem; border: 1px solid #cbd5e1; border-radius: 999px; background: #ffffff; color: #0f172a; box-shadow: 0 10px 24px rgba(15,23,42,0.08); }}\n    .toolbar .legend {{ display: flex; flex-wrap: wrap; gap: 0.75rem; }}\n    .badge {{ display: inline-flex; align-items: center; gap: 0.35rem; padding: 0.35rem 0.8rem; border-radius: 999px; font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.01em; }}\n    .badge.critical {{ background: #fef2f2; color: #b91c1c; border: 1px solid #fecaca; }}\n    .badge.high {{ background: #fef3c7; color: #b45309; border: 1px solid #fde68a; }}\n    .badge.medium {{ background: #fef9c3; color: #78350f; border: 1px solid #fde68a; }}\n    .badge.low {{ background: #dcfce7; color: #166534; border: 1px solid #bbf7d0; }}\n    .badge.info {{ background: #dbeafe; color: #1d4ed8; border: 1px solid #bfdbfe; }}\n    .overview {{ display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom: 1.5rem; }}\n    .metric {{ padding: 1rem 1.1rem; border-radius: 16px; background: #ffffff; border: 1px solid #dbeafe; box-shadow: 0 18px 40px rgba(15, 23, 42, 0.05); }}\n    .metric strong {{ display: block; font-size: 1rem; color: #334155; margin-bottom: 0.4rem; }}\n    .metric span {{ display: block; font-size: 1.8rem; font-weight: 700; color: #0f172a; }}\n    .finding-list {{ display: grid; gap: 1rem; }}\n    details.finding {{ border-radius: 18px; overflow: hidden; background: #ffffff; border: 1px solid rgba(148, 163, 184, 0.3); box-shadow: 0 18px 45px rgba(15, 23, 42, 0.06); }}\n    details.finding summary {{ list-style: none; padding: 1.2rem 1.4rem; cursor: pointer; display: grid; grid-template-columns: 1fr auto; gap: 1rem; align-items: center; position: relative; }}\n    details.finding summary::-webkit-details-marker {{ display: none; }}\n    details.finding summary::after {{ content: '▾'; position: absolute; right: 1.4rem; top: 50%; transform: translateY(-50%); transition: transform 0.2s ease; color: #334155; }}\n    details.finding[open] summary::after {{ transform: translateY(-50%) rotate(180deg); }}\n    .finding-summary {{ display: grid; gap: 0.5rem; }}\n    .finding-summary h2 {{ margin: 0; font-size: 1.1rem; line-height: 1.4; color: #0f172a; }}\n    .finding-meta {{ display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; color: #64748b; font-size: 0.95rem; }}\n    .finding-body {{ padding: 0 1.4rem 1.4rem; color: #334155; line-height: 1.8; border-top: 1px solid rgba(148, 163, 184, 0.12); background: #f8fafc; }}\n    .finding-body p {{ margin: 0.95rem 0; }}\n    .field-label {{ font-weight: 700; color: #0f172a; }}\n    @media (max-width: 640px) {{ header {{ padding: 1.5rem 1rem 1rem; }} details.finding summary {{ padding: 1rem 1.2rem; }} .finding-body {{ padding: 0 1.2rem 1.2rem; }} }}\n  </style>\n  <script>\n    function normalize(text) {{ return text.toLowerCase(); }}\n    function onSearch(event) {{\n      const query = normalize(event.target.value.trim());\n      document.querySelectorAll('.finding').forEach(section => {{\n        const title = normalize(section.dataset.title || '');\n        const category = normalize(section.dataset.category || '');\n        const severity = normalize(section.dataset.severity || '');\n        const body = normalize(section.innerText || '');\n        const visible = query.length === 0 || title.includes(query) || category.includes(query) || severity.includes(query) || body.includes(query);\n        section.style.display = visible ? 'block' : 'none';\n      }});
    }}\n  </script>\n</head>\n<body>\n  <header>\n    <h1>ScopeGuard Report</h1>\n    <p>Findings are sorted by severity with the most urgent issues first. Use the search filter to narrow results by title, category, severity, or content.</p>\n  </header>\n  <main>\n    <div class=\"toolbar\">\n      <input type=\"search\" placeholder=\"Search findings...\" oninput=\"onSearch(event)\">\n      <div class=\"legend\">\n        <span class=\"badge critical\">Critical</span>\n        <span class=\"badge high\">High</span>\n        <span class=\"badge medium\">Medium</span>\n        <span class=\"badge low\">Low</span>\n        <span class=\"badge info\">Info</span>\n      </div>\n    </div>\n    <div class=\"overview\">\n      <div class=\"metric\">\n        <strong>Total findings</strong>\n        <span>{total}</span>\n      </div>\n      <div class=\"metric\">\n        <strong>Critical</strong>\n        <span>{critical}</span>\n      </div>\n      <div class=\"metric\">\n        <strong>High</strong>\n        <span>{high}</span>\n      </div>\n      <div class=\"metric\">\n        <strong>Medium</strong>\n        <span>{medium}</span>\n      </div>\n      <div class=\"metric\">\n        <strong>Low</strong>\n        <span>{low}</span>\n      </div>\n      <div class=\"metric\">\n        <strong>Info</strong>\n        <span>{info}</span>\n      </div>\n    </div>\n    <div class=\"finding-list\">\n      {items}\n    </div>\n  </main>\n</body>\n</html>\n",
        total = total,
        critical = critical,
        high = high,
        medium = medium,
        low = low,
        info = info,
        items = items
    )
}
