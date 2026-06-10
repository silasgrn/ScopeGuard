
# ScopeGuard

ScopeGuard is a Rust-first, offline infrastructure security auditing tool for Linux hosts, containers, and virtualization environments. It targets homelab operators, system administrators, and developers who want a fast, local analysis of configuration mistakes and exposed services.

**Quick overview**

- Language: Rust
- Target: Linux (tested on Debian/Ubuntu)
- Outputs: Human terminal output, JSON, interactive HTML report

**Project progress (actual)**

- MVP (v1.0) implementation: ~25% complete
- Full roadmap (v2/v3 features included): ~30% complete

These are conservative, reality-based estimates: most modules are scaffolds or work-in-progress. The only fully working audit at the moment is the firewall audit backend and its parsing logic.

**What currently works**

- CLI: `scan`, `report` (basic runner present)
- Fully implemented audit:
  - Firewall: detection and parsing for `nftables`, `iptables`, and UFW (runtime rules parsing and scope-aware findings)

**Work in progress / placeholders**

- Network listener enumeration: sudo/root fallback added, but behavior may be incomplete on some hosts
- Container runtime inspection (Docker/Podman): implemented but edge-cases remain
- Host checks (SSH) and WireGuard parsing: present but not fully validated across environments
- Services, attack-surface graph, VM discovery: scaffolding and partial implementations exist

**Planned / remaining work**

- Stabilize and test Network, Container, Host, WireGuard modules across target distros
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
