# PROJECT SCOPE

## PROJECT NAME

**ScopeGuard**

---

## DESCRIPTION

ScopeGuard is an **open-source infrastructure security auditing tool** for Linux servers, homelabs, and self-hosted environments.

It analyzes system configuration and infrastructure components to detect **misconfigurations, exposure risks, and attack surface weaknesses**.

It focuses on:

* Docker / Podman container security
* Virtual machines (KVM, QEMU, Proxmox, VirtualBox)
* Network services and open ports
* Firewall configurations (nftables, iptables)
* WireGuard VPN setups
* Host system security configuration
* Service discovery and exposure analysis
* Attack surface modeling

ScopeGuard is designed to sit between **lightweight shell scripts** and **enterprise security platforms** (e.g. Wazuh, OpenSCAP), offering a **fast, offline-first, developer-friendly auditing tool**.

---

## TARGET USERS

* Homelab operators
* Linux system administrators
* DevOps engineers
* Self-hosting users
* Cybersecurity learners
* Small businesses
* Infrastructure engineers

---

## NON-GOALS

ScopeGuard is NOT:

* An EDR system
* An antivirus
* A real-time monitoring agent
* A SIEM platform
* A vulnerability scanner for external targets
* A penetration testing framework
* An exploitation tool
* An IDS/IPS system

---

# MVP SCOPE (v1.0)

## CLI

```bash
scopeguard scan
scopeguard scan --json
scopeguard report
```

---

## OUTPUT FORMATS

* Human-readable terminal output
* JSON output (machine-readable)
* HTML security report

---

## SEVERITY MODEL

* CRITICAL
* HIGH
* MEDIUM
* LOW
* INFO

---

## FINDING FORMAT

Each finding contains:

* Title
* Description
* Risk explanation
* Recommendation
* Severity level

---

# CORE MODULES

## HOST SECURITY

SSH Audit:

* PermitRootLogin
* PasswordAuthentication
* PubkeyAuthentication
* Empty password detection
* Weak configuration detection

---

## NETWORK SECURITY

Port scanning (local system):

* TCP ports
* UDP ports
* Service bindings:

  * localhost
  * specific interface
  * 0.0.0.0 (public exposure)

Detected exposed services:

* PostgreSQL
* MySQL
* Redis
* MongoDB
* Elasticsearch

---

## FIREWALL AUDIT

Supported:

* nftables
* iptables

Checks:

* Default policy validation
* Missing firewall detection
* Overly permissive rules
* Public admin port exposure

---

## CONTAINER SECURITY

Docker / Podman checks:

* Root containers
* Privileged containers
* Docker socket exposure
* Host network mode
* Host PID/IPC namespace sharing
* Writable host mounts
* Excess capabilities
* Missing resource limits

Image checks:

* Outdated images
* Unknown images
* Use of `latest` tag

---

## VIRTUALIZATION SECURITY

KVM / QEMU:

* VM discovery
* Network exposure analysis
* Unsafe bridging detection

Proxmox:

* VM/LXC discovery
* Missing firewall
* Missing backups/snapshots

---

## WIREGUARD AUDIT

Checks:

* Stale peers
* Inactive connections
* Traffic anomalies
* Unused peers

---

## SERVICE DISCOVERY

Detects:

* Web servers (Nginx, Apache, Caddy, Traefik)
* Databases
* File services (Samba, FTP)
* Mail servers
* Cache systems (Redis, etc.)

---

## ATTACK SURFACE MODEL

ScopeGuard builds a **local graph model** of infrastructure exposure.

### Nodes:

* Host
* VM
* Container
* Service
* Database
* VPN
* User

### Edges:

* CONNECTED_TO
* DEPENDS_ON
* EXPOSES
* ROUTES_THROUGH

---

## SECURITY SCORE

Base: 100

Penalties:

* CRITICAL: -25
* HIGH: -10
* MEDIUM: -5
* LOW: -1

Score classification:

* 90–100: Excellent
* 75–89: Good
* 50–74: Moderate
* 0–49: High Risk

---

## HTML REPORT

Includes:

* Findings overview
* Severity distribution
* Security score
* Attack surface graph
* Recommendations

Features:

* Offline support
* Dark mode
* Exportable report

---

## PLUGIN SYSTEM (v2)

Core interface:

* name()
* version()
* run()

Plugins:

* SSH
* Docker / Podman
* Firewall
* Network
* VM
* WireGuard
* Services

---

## HISTORY (v2)

```bash
scopeguard history
```

Stores:

* Scan results
* Findings snapshots
* Security score evolution

Features:

* Trend analysis
* Diff comparisons

---

## AUTO-FIX SYSTEM (v3)

Examples:

```bash
scopeguard fix ssh-disable-root-login
scopeguard fix firewall-default-policy
scopeguard fix docker-remove-privileged
```

Features:

* Dry-run mode
* User confirmation
* Rollback support

---

## GITHUB ACTION (v3)

Use cases:

* Docker Compose security review
* CI/CD pipeline security checks
* Pull request risk scoring

Outputs:

* PR comments
* Security score summaries
* Inline findings

---

## OUT OF SCOPE (INITIAL RELEASE)

* Multi-host orchestration
* Cloud dashboard
* SIEM integration
* Real-time monitoring
* IDS/IPS
* CVE database integration
* Exploit detection
* Active response automation

---

## SUCCESS CRITERIA

### v1

* Works on Ubuntu & Debian
* Detects Docker misconfigurations
* Detects SSH misconfigurations
* Detects open services
* Generates security score

### v2

* VM support
* WireGuard support
* Attack surface graph

### v3

* Auto-fix engine
* GitHub Actions integration
* Plugin ecosystem

---

# TECH STACK

## CORE LANGUAGE

### Rust (Primary)

ScopeGuard is built as a **Rust-first security tool**.

Why Rust:

* Memory safe
* High performance
* Ideal for system-level scanning
* No runtime dependencies
* Perfect for offline tools

---

## ARCHITECTURE

### Single Binary Design

* One compiled CLI binary
* No external runtime dependencies
* Fully offline capable
* Minimal resource usage

---

## OPTIONAL EXTENSIONS

* Rust native plugins
* WASM-based plugins (sandboxed)
* Optional external tooling integrations

---

## RUST STACK

* clap → CLI
* serde / serde_json → data handling
* tokio → async execution
* nix → Linux system interaction
* sysinfo → system inspection
* regex → parsing engine
* tracing → logging
* rayon → parallel scanning

---

## BUILD TARGET

* Linux-first
* Static binary preferred
* Fast startup
* Low memory footprint

---

## LICENSE

* MIT (recommended)
  or
* Apache-2.0

---

# REPOSITORY STRUCTURE

```text
scopeguard/
├── src/
│   ├── core/
│   ├── cli/
│   ├── scanner/
│   ├── host/
│   ├── network/
│   ├── ssh/
│   ├── docker/
│   ├── firewall/
│   ├── vm/
│   ├── wireguard/
│   ├── services/
│   ├── scoring/
│   ├── report/
│   ├── attack_surface/
│   └── plugin/
├── plugins/
├── docs/
├── examples/
├── .github/
├── Cargo.toml
├── README.md
└── LICENSE
```
