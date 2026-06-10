# ScopeGuard

ScopeGuard ist ein Rust-basiertes Tool zur Offline-Sicherheitsaudits von Linux-Hosts, Containern und Virtualisierungsumgebungen. Es richtet sich an Homelab-Operatoren, Admins und Entwickler, die lokale Infrastruktur auf Konfigurationsfehler und exponierte Services prüfen möchten.

**Kurzüberblick**

- Sprache: Rust
- Zielplattform: Linux (Debian/Ubuntu getestet)
- Ausgabe: Terminal, JSON, interaktiver HTML-Report

**Projektfortschritt**

- MVP (v1.0) Implementierung: ca. 90% abgeschlossen
- Gesamtroadmap (inkl. v2/v3 Features): ca. 70% abgeschlossen

Diese Werte sind Näherungswerte basierend auf implementierten Audit-Modulen, Report-Funktionalität und Integrationstests im Repo.

**Was funktioniert (Auswahl)**

- CLI: `scan`, `report` (JSON & HTML)
- Audit-Module:
  - Host: SSH-Konfiguration und grundsätzliche Systemchecks
  - Netzwerk: lokale Listener-Erkennung mit Root-/sudo-Fallback
  - Firewall: Erkennung und Parsing von `nftables`, `iptables` und UFW-Regeln
  - Container: Laufzeit-Inspektion für Docker und Podman (Container, Host-Mounts, Netzmodus)
  - Virtualisierung: VM-Erkennung und Exposure-Analyse
  - WireGuard: Laufzeitprüfung von Peers (`wg show`), inaktive/fehlende Peers melden
  - Services: Scope-gesteuerte Service-Reporting (keine statischen Platzhalter mehr)
  - Attack-surface Modell: lokale Graph-Building-Logik

**Was noch offen / geplant**

- Vollständige Plugin-API und dokumentierte Erweiterungs-Schnittstelle (v2)
- Automatische Fixes / Aktionen (v3)
- CI/GitHub Action Integrationen (v3)
- Erweiterte Trend- und History-Funktionen

## Schnellstart

Lokalen Scan starten (Entwicklung):

```bash
cargo run -- scan
cargo run -- scan --json > last-scan.json
cargo run -- report
```

HTML-Report erzeugen und lokal öffnen:

```bash
cargo run -- report && xdg-open scopeguard-report.html
```

## Konfiguration & Scope

Lade oder passe deine Scope-Datei an (`SCOPE.md` beschreibt das Projekt-Scope). Scope-gestützte Regeln setzen Findings auf `info` wenn sie innerhalb des definierten Betriebsbereichs liegen.

## Mitwirken

- Issues/PRs willkommen — siehe CONTRIBUTING via GitHub
- Code-Style: Rustfmt, Clippy

## Kontakt

Projekt- und Maintainer-Informationen findest du im Repo.

---

Weitere Details und das vollständige Scope-Design stehen in [SCOPE.md](SCOPE.md).
