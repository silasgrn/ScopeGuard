# ScopeGuard

ScopeGuard is a Rust-first, offline infrastructure security auditing tool for Linux hosts, containers, and virtualization environments. It targets homelab operators, system administrators, and self-hosted operators who want a fast, local analysis of configuration issues, exposed services, and firewall posture.

**Quick overview**

- Language: Rust
- Platform: Linux
- Outputs: Human-readable terminal output, JSON, HTML report
- Current focus: configuration auditing, network exposure, firewall inspection, SSH hardening

## What the project can check today

| Area | Current coverage |
| --- | --- |
| CLI / report generation | `scan`, `report`, JSON output, HTML report creation |
| Firewall audit | Active firewall backend detection, `nftables`/`iptables`/`ufw` parsing, permissive default policy detection, inbound accept rule analysis, scope-aware findings with rule-level recommendations |
| SSH / host security | `sshd_config` parsing, insecure option detection, missing host key checks, empty password hash detection in `/etc/shadow` |
| Network security | Listening socket enumeration via `ss`, `netstat` fallback, public service detection, high-risk exposed service alerts, high public listener count warnings |
| Scope-aware services | Uses configured scope definitions, marks in-scope exposures as informational, highlights out-of-scope public services |

## What is still missing compared to `SCOPE.md`

| Area | Remaining coverage needed |
| --- | --- |
| Host security | Additional hardening checks beyond SSH, password/lockout policy auditing, account control and PAM inspection |
| Network security | Full port scanning, richer service discovery, interface-level exposure analysis, network zone classification |
| Firewall audit | Policy analysis for permissive defaults, specific rule-level security recommendations |
| Container security | Docker/Podman runtime inventory, root/privileged container detection, socket exposure, host network/PID/IPC sharing, mount safety, capability/resource limit checks, image hygiene |
| Virtualization security | KVM/QEMU VM discovery, unsafe bridge detection, Proxmox VM/LXC discovery, guest firewall checks, backup/snapshot analysis |
| WireGuard audit | Stale/unused peer detection, inactive connection analysis, peer traffic anomalies |
| Service discovery & attack surface modeling | Automatic discovery beyond defined scope, attack surface graph generation, service-to-network mapping |

## Quickstart

Run a local scan:

```bash
cargo run -- scan
cargo run -- scan --json > last-scan.json
cargo run -- report
```

Generate the HTML report and open it:

```bash
cargo run -- report && xdg-open scopeguard-report.html
```

## Contributing

- Issues and PRs welcome
- Code style: `rustfmt`, `clippy`

---

For a complete view of project scope and intended coverage, see [SCOPE.md](SCOPE.md).
