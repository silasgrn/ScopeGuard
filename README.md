# ScopeGuard

ScopeGuard is a Rust-based infrastructure security auditing tool for Linux systems. It is currently in active development with a working CLI, reporting system, and concrete audit modules.

## Current status

- Rust crate initialized and compiles successfully with `cargo build`
- CLI implemented with `scan` and `report` commands
- JSON / HTML report rendering implemented
- Structured findings and severity model in place
- Implemented audit components:
  - Host SSH configuration inspection
  - Network listener enumeration
  - Firewall backend detection (`nftables`, `iptables`, `ufw`)
  - Container security checks
  - Virtualization discovery
  - Service and scope-aware listener reporting
  - WireGuard peer status
  - Attack surface discovery
- `scopeguard-report.html` is ignored in Git

## Usage

```bash
cargo run -- scan
cargo run -- scan --json
cargo run -- report
cargo run -- report --json
```

## Notes

Audit modules report actual findings from the host where the scanner runs.
