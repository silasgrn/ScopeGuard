use clap::{Parser, Subcommand};

use crate::audit::run_all_audits;
use crate::report::{render_html, render_human, render_json};
use crate::scope::ScopeFile;

#[derive(Parser)]
#[command(name = "scopeguard")]
#[command(about = "ScopeGuard infrastructure security auditing tool", long_about = None)]
pub struct CommandLine {
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Run a local security scan and print findings
    Scan {
        #[arg(long, help = "Emit JSON output")]
        json: bool,
        #[arg(long, help = "Read a JSON scope file with service definitions")]
        scope: Option<String>,
    },
    /// Generate a security report
    Report {
        #[arg(
            long,
            default_value = "scopeguard-report.html",
            help = "HTML report output path"
        )]
        output: String,
        #[arg(long, help = "Write JSON report instead of HTML")]
        json: bool,
    },
}

pub fn run() -> Result<(), String> {
    let command = CommandLine::parse();
    let scope_file = match &command.command {
        Action::Scan { scope, .. } => {
            if let Some(path) = scope {
                Some(ScopeFile::load(path)?)
            } else {
                None
            }
        }
        _ => None,
    };

    let findings = run_all_audits(scope_file.as_ref());

    match command.command {
        Action::Scan { json, .. } => {
            if json {
                let serialized = render_json(&findings);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serialized).map_err(|err| err.to_string())?
                );
            } else {
                print!("{}", render_human(&findings));
            }
        }
        Action::Report { output, json } => {
            if json {
                let serialized = render_json(&findings);
                std::fs::write(
                    &output,
                    serde_json::to_string_pretty(&serialized).map_err(|err| err.to_string())?,
                )
                .map_err(|err| err.to_string())?;
                println!("JSON report written to {output}");
            } else {
                let html = render_html(&findings);
                std::fs::write(&output, html).map_err(|err| err.to_string())?;
                println!("HTML report written to {output}");
            }
        }
    }

    Ok(())
}
