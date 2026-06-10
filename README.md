
# ScopeGuard

ScopeGuard is a Rust-first, offline infrastructure security auditing tool for Linux hosts, containers, and virtualization environments. It targets homelab operators, system administrators, and developers who want a fast, local analysis of configuration mistakes and exposed services.

**Quick overview**

- Language: Rust
- Target: Linux (tested on Debian/Ubuntu)
- Outputs: Human terminal output, JSON, interactive HTML report

**Project progress**

- MVP (v1.0) implementation: ~90% complete
- Full roadmap (v2/v3 features included): ~70% complete

Progress estimates are approximate, based on implemented audit modules, report rendering, and integration tests found in the repository.

**What works (selected)**

- CLI: `scan`, `report` (JSON & HTML)
- Audit modules:
  - Host: SSH configuration checks and basic host sanity checks
  - Network: local listener enumeration with root/sudo fallback
  - Firewall: detection and parsing for `nftables`, `iptables` and UFW
  - Container: runtime inspection for Docker and Podman (containers, host mounts, network mode)
  - Virtualization: VM discovery and exposure analysis
  - WireGuard: runtime peer inspection (`wg show`), inactive/missing peers reported
  - Services: scope-driven service reporting (no more static placeholders)
  - Attack surface: local graph-building logic

**Planned / remaining work**

- Complete plugin API and documented extension interface (v2)
- Auto-fix actions / remediation engine (v3)
- CI / GitHub Actions integration (v3)
- Enhanced history and trend analysis

## Quickstart

Run a local scan (development):

```bash
cargo run -- scan
cargo run -- scan --json > last-scan.json
cargo run -- report
```

Generate the HTML report and open it locally:

```bash
cargo run -- report && xdg-open scopeguard-report.html
```

## Configuration & scope

Edit your scope definition to match the assets you consider in-scope — `SCOPE.md` documents the project scope. Findings that fall inside the configured scope are downgraded to `info` where appropriate.

## Contributing

- Issues and PRs welcome — see CONTRIBUTING on the repository
- Code style: `rustfmt`, `clippy`

## Contact

Maintainers and project details are available in the repository.

---

For more details and the full scope design see [SCOPE.md](SCOPE.md).
