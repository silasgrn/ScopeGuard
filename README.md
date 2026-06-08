# ScopeGuard

ScopeGuard is a Rust-based infrastructure security auditing tool for Linux systems. It is currently in initial development with a working CLI, reporting system, and placeholder audit modules.

## Current status

- Rust crate initialized and compiles successfully with `cargo build`
- CLI implemented with `scan` and `report` commands
- JSON / HTML report rendering implemented
- Structured findings and severity model in place
- Placeholder audits implemented for:
  - Host SSH configuration
  - Network listener inspection
  - Firewall backend detection (`nftables` / `iptables`)
  - Container security checks
  - Virtual machine audit placeholders
  - Service discovery placeholders
  - WireGuard peer status
  - Attack surface placeholder modeling
- `scopeguard-report.html` is ignored in Git

## Usage

```bash
cargo run -- scan
cargo run -- scan --json
cargo run -- report
cargo run -- report --json
```

## Notes

The current implementation uses dummy and placeholder data for many audit components. The project structure and report flow are set up so that the placeholder logic can be replaced with real system discovery and scanning later.
