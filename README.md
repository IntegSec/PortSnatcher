# PortSnatcher

**Catch ephemeral ports the moment they open — fingerprint, hold open, and hand off to the pentester before the window closes.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Status](https://img.shields.io/badge/status-v1.2.0%20%E2%80%94%20real%20SYN%20race%20on%20Linux-brightgreen)](./CHANGELOG.md)
[![CI](https://github.com/IntegSec/PortSnatcher/actions/workflows/ci.yml/badge.svg)](https://github.com/IntegSec/PortSnatcher/actions/workflows/ci.yml)
[![Platform](https://img.shields.io/badge/platform-linux_%7C_macOS_%7C_windows-lightgrey)]()
[![Made by IntegSec](https://img.shields.io/badge/made_by-IntegSec-black)](https://integsec.com)

> **Current status — April 2026 / v1.2.0:** the SYN-race capability is
> real on Linux. `RawEngine` runs a `pnet` AF_PACKET SYN spray + pcap
> SYN-ACK receive + kernel-connect handoff at up to 10,000 pps/target
> (requires `CAP_NET_RAW`). macOS and Windows still run the connect-engine
> with a `"raw"` label while the BPF / WinDivert ports are written — flagged
> honestly in `BACKEND_STATUS` and the CHANGELOG, not hidden. `portsnatcher/v1`
> event schema frozen; scope-file format cross-compatible with
> [`IntegSec/agentic-pentest-proxy`](https://github.com/IntegSec/agentic-pentest-proxy).
> [Spec](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md) ·
> [Operator guide](./docs/operator-guide.md) · [CHANGELOG](./CHANGELOG.md).

---

## Why PortSnatcher exists

Modern pentest targets expose services on **ephemeral, short-lived TCP ports** — cloud metadata helpers, auto-scaling admin interfaces, flapping internal services, reconnection-window sockets, debug listeners that open for milliseconds during a deploy. Classic scanners are the wrong shape for this:

- `nmap`, `masscan`, `zmap`, `unicornscan` — one-shot. A port that's open for 200ms during your scan is either in the results or isn't; by the time you see it, it's gone.
- `knockd` / port-knocking tools — detect, don't exploit.
- Burp Collaborator / Interactsh — listen on your infrastructure, don't hunt on theirs.
- `pwncat`, `responder` — post-connection, don't race.

PortSnatcher is the first tool purpose-built for the **race**. It watches a scoped set of targets continuously, wins the race to SYN/ACK the moment a port opens, fingerprints the service on fresh connections (one probe per connection, nothing destructive unless authorized), stands up a local hold-open tunnel so you can attack through Burp or any TCP-speaking tool before the port closes, and pokes you via desktop toast / webhook the moment it catches.

**It's the tool you reach for when `nmap` gave you nothing but you know services are flashing open on that host.**

## The 30-second demo (target UX)

```bash
# On the pentester's laptop — targeting a scope-file-defined engagement
$ portsnatcher --config engagement.toml
[09:14:02] PortSnatcher v1.2.0 — engagement ENG-2026-0142
[09:14:02] Profile: internal  |  Engine: raw  |  Targets: 10.20.0.0/16 (256 hosts)
[09:14:02] Ports: ephemeral-iana (49152-65535)  |  Rate cap: 50000 pps
[09:14:02] Event bus: http://127.0.0.1:7177/events  (token in ~/.config/portsnatcher/bus-token)
[09:14:02] Scope file: ./scope.json (compatible with agentic-pentest-proxy)
[09:14:02] Watching...

[09:14:47] CATCH  10.20.5.17:54283  (window: 180ms)  engine=raw  syn_rtt=2ms
           └─ fingerprint: HTTP/1.1, Server: nginx/1.25.3, TLS: no
           └─ hold-open:   localhost:7101  (dumb_tunnel, keepalive engaged)
           └─ desktop toast sent, webhook POST ok
           → attach Burp to 127.0.0.1:7101 to work the service
```

**From port opening to live Burp-ready tunnel: typically ~2 seconds.** The toast fires while the fingerprinter is still running — the tunnel is up before the banner shows up on your screen.

## How it works

```
 targets.json  ────┐
                    │
 scope.json   ────┐ │      ┌─────────────────────────────────────────┐
                  │ │      │           PortSnatcher                  │
 config.toml  ────┼─┴──────┤                                         │
                  │        │  ┌──────────┐   ┌──────────────┐        │
                  └────────┼──▶ Engine   │──▶│ Fingerprinter│        │
                           │  │(raw|conn)│   │ (probe ladder│        │
                           │  └──────────┘   └──────────────┘        │
                           │        │              │                 │
                           │        ▼              ▼                 │
                           │   ┌─────────────────────────┐           │
                           │   │    Event Bus (v1)       │           │
                           │   │  tokio::broadcast +     │           │
                           │   │  SSE/WebSocket server   │           │
                           │   └──────┬──────────────────┘           │
                           │          │                              │
                           │  ┌───────┼────────┬───────────┐         │
                           │  ▼       ▼        ▼           ▼         │
                           │ TUI   JSONL  Toast/Webhook  Hold-Open   │
                           │                              Proxy      │
                           │                                │        │
                           └────────────────────────────────┼────────┘
                                                            ▼
                                              127.0.0.1:71xx (attach here)
```

Everything communicates through a versioned JSON event bus. The same stream you see in the TUI is what a webhook receives, what `events.jsonl` records, and what the future Burp extension will subscribe to over HTTP.

## Key features

| | |
|---|---|
| **`RawEngine` (Linux, real SYN race since v1.2)** | `pnet` AF_PACKET SYN spray + pcap SYN-ACK receive + kernel-connect handoff. Sub-100ms detection of ephemeral ports at up to ~10,000 pps/target. Requires `CAP_NET_RAW`. On macOS/Windows the same engine falls back to a connect-labelled scheduler pending the BPF / WinDivert ports (v1.3). |
| **`ConnectEngine`** | Unprivileged async `connect()` with `FuturesUnordered` concurrency. Works in containers, locked-down jumpboxes, CI. Same events, same pipeline. Use when you don't have `CAP_NET_RAW`. |
| **Probe ladder, not probe list** | Passive banner read first (zero bytes sent), then TLS ClientHello, then port-aware protocol probes — one per fresh connection. Never chains a destructive probe after a soft one. Nine probes in v1 (HTTP, TLS, SSH, Redis, Mongo, Postgres, SMB, banner). |
| **Hold-open tunnel** | The moment a port is caught, we stand up `localhost:71xx` piping bytes to the target. You point Burp / ncat / your custom exploit at it before the port closes. Optional TLS MITM for HTTPS catches, using a reusable on-disk CA. |
| **Scope-aware probes** | Probes are tagged with [technique categories](https://github.com/IntegSec/agentic-pentest-proxy/blob/master/examples/scope-manifest.json) — `recon`, `web_app`, `api_testing`, `ssl_tls`, `destructive`. Probes without authorized coverage are skipped and audit-logged. |
| **Stable event schema** | `portsnatcher/v1` events are a frozen JSON contract. Additive-only forever. Your Burp extension, SOC pipeline, or custom tooling can depend on it. |
| **Real-time handoff** | Desktop toasts, Slack/Discord/ntfy/PagerDuty webhooks, terminal TUI (`--tui`), SSE/WebSocket bus — all fed from the same stream. |
| **Safety first** | Scope file required; hard-deny on loopback/link-local; global + per-target pps caps; explicit-target rule; `--i-know-what-im-doing` flag for overrides (and yes, it's literally named that). Every decision logged to `audit.log`. |

## Cross-tool scope compatibility

PortSnatcher consumes the **same JSON scope-file format** as IntegSec's [`agentic-pentest-proxy`](https://github.com/IntegSec/agentic-pentest-proxy). One file describes your engagement; both tools honor it. PortSnatcher adds a namespaced `portsnatcher` section for port-specific policy that the proxy ignores cleanly.

```json
{
  "engagement_id": "ENG-2026-0142",
  "client": "Acme Corp",
  "operator": "you@yourshop.com",
  "authorized_targets": {
    "ip_ranges": ["10.10.10.0/24"],
    "domains": ["*.acme.com"]
  },
  "excluded_targets": ["10.10.10.99"],
  "authorized_techniques": ["recon", "web_app", "api_testing", "ssl_tls"],
  "excluded_techniques": ["dos", "destructive"],
  "engagement_window": {
    "start": "2026-04-22T08:00:00Z",
    "end":   "2026-05-06T17:00:00Z"
  },
  "portsnatcher": {
    "port_policy": {
      "include": ["ephemeral-iana", "22", "80", "443"]
    }
  }
}
```

## Profiles — three postures, one codebase

| | **internal** | **external** | **ctf** |
|---|---|---|---|
| Default engine | raw | raw | raw |
| Global pps cap | 50,000 | 1,000 | 100,000 |
| Per-target cap | 2,000 | 200 | 10,000 |
| Probe ladder | full | minimal | full + aggressive |
| Toast on catch | yes | no | yes |
| Scope file required | yes | yes (strict) | no (lab) |

`--profile` is a one-flag way to pick a coherent default posture. Override any individual setting when you need to.

## Roadmap

### Shipped (v1.0 → v1.2)
- [x] Design + five phase plans ([spec](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md))
- [x] `ps-core` (scope, config, frozen `portsnatcher/v1` event schema, insta snapshots)
- [x] `ps-engine` — `ConnectEngine` + `RawEngine`
- [x] `ps-fingerprint` — nine-probe ladder with fresh-connection discipline
- [x] `ps-proxy` — dumb tunnel + TLS MITM with `rcgen`-signed CA
- [x] `ps-bus` — SSE + WebSocket + bearer-token auth
- [x] `ps-notify` — terminal / JSONL / webhook / desktop sinks
- [x] `ratatui` TUI via `--tui`
- [x] Linux / macOS / Windows CI matrix + fmt + clippy gate
- [x] Fuzz targets + `cargo-deny` license policy
- [x] Signed `cargo-dist`-style prebuilts via GitHub Releases
- [x] Live-engagement E2E smoke test
- [x] **Real Linux SYN race** (v1.2): `pnet` AF_PACKET + pcap + kernel-connect handoff

### v1.3 — next
- macOS BPF port of `SynRace`
- Windows WinDivert port of `SynRace`
- IPv6 support in target plan, scope guard, and SynRace
- Multi-NIC per-target source-IP routing

### v1.4+
- First-party **Burp Suite extension** (Montoya API) subscribing to the event bus
- Caido / ZAP plugins following the same pattern
- Web dashboard for the event bus
- crates.io publish (`cargo install integsec-portsnatcher`) once the registry token is configured

### v2+
- UDP support
- Deeper protocol-specific probe modules (LDAP, Kerberos, proprietary binary protocols)
- Distributed mode (multiple PortSnatcher probes feeding one bus)

## Safety and ethics

PortSnatcher is a **professional pentest tool**, not a script-kiddie toy. It refuses to run without a scope file. It refuses internet-wide scanning. It logs every decision — including every packet it *chose not to send* — to an audit trail that belongs in your client report. The defaults are conservative; the bypass flag is intentionally awkward to type.

**Use it on engagements you're authorized to perform.** If your engagement letter doesn't cover PortSnatcher's behavior, don't run it. The Apache-2.0 license gives you rights to the code; it does not give you rights to the networks you point it at.

## Supported platforms

| | Linux | macOS | Windows |
|---|---|---|---|
| `ConnectEngine` | yes | yes | yes |
| `RawEngine` — real SYN race (v1.2+) | **yes** (`pnet` AF_PACKET + pcap) | not yet (v1.3: BPF) | not yet (v1.3: WinDivert) |
| `RawEngine` — connect-labelled fallback | only if `SynRace` fails to init | yes (current) | yes (current) |
| Optional `nftables` RST-drop kassist | installed when `nft` available | n/a | n/a |
| Requires elevation for `RawEngine` | `CAP_NET_RAW` (`setcap cap_net_raw,cap_net_admin=eip`) | root | admin |

Linux is where the headline capability actually lives today. macOS and Windows are solid for the `ConnectEngine`, the hold-open proxy, TLS MITM, the TUI, and the full event-bus stack — they just don't do the real sub-100ms SYN race yet. That's v1.3.

**Honest check:** the real race only improves catch-rate for ports that open for milliseconds-to-seconds. If your target is serving a long-lived HTTPS endpoint on 443, the ConnectEngine on any OS is already fine.

## Install

**Prebuilt binary (recommended).** Grab the archive for your OS+arch from the
[latest GitHub Release](https://github.com/IntegSec/PortSnatcher/releases/latest)
and unpack it somewhere on your `$PATH`. Per release, we ship:

- `portsnatcher-v1.2.0-x86_64-unknown-linux-gnu.tar.gz`
- `portsnatcher-v1.2.0-x86_64-apple-darwin.tar.gz`
- `portsnatcher-v1.2.0-aarch64-apple-darwin.tar.gz`
- `portsnatcher-v1.2.0-x86_64-pc-windows-msvc.zip`

On Linux, grant the real-SYN-race engine the capabilities it needs
(otherwise it falls back to the connect-labelled scheduler):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(which portsnatcher)"
```

**Building from source:**

```bash
git clone https://github.com/IntegSec/PortSnatcher
cd PortSnatcher
cargo build --release --bin portsnatcher
./target/release/portsnatcher --help
```

**`cargo install`** will land once the `CARGO_REGISTRY_TOKEN` repo secret is configured (v1.4 roadmap):

```bash
cargo install integsec-portsnatcher  # NOT YET published to crates.io
```

## Contributing

PortSnatcher is open to community contributions. Two rules are non-negotiable:

1. **The `portsnatcher/v1` event schema is frozen.** Adding a new optional field is OK. Removing or renaming a field is a `v2` bump and requires coordinated consumer updates. The `insta` snapshots in `crates/ps-core/tests/snapshots/` are the enforcement mechanism — a PR that changes them must explain why.
2. **Scope-file compatibility with `agentic-pentest-proxy` is a stability contract.** Anything that changes the top-level fields is a breaking change.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for dev setup, commit conventions, and the PR checklist. For security-sensitive reports, see [`SECURITY.md`](./SECURITY.md).

## Prior art and influences

PortSnatcher stands on the shoulders of:
- `nmap`, `masscan`, `zmap`, `unicornscan` — port-scanning state of the art
- `pnet` — the raw-socket + pcap crate that makes `RawEngine` tractable on Linux
- `rustls` — the TLS implementation used for the MITM proxy
- `ratatui`, `tokio`, `axum` — Rust's superb async ecosystem
- `rcgen` — on-disk CA generation for the TLS MITM
- Burp Collaborator / Interactsh — prior art for out-of-band handoff patterns
- IntegSec's [`agentic-pentest-proxy`](https://github.com/IntegSec/agentic-pentest-proxy) — sister tool and source of the scope-file format

We are not aware of any prior tool combining continuous SYN-level racing, short-window fingerprinting on fresh connections, and pentester-in-the-loop hold-open handoff in one package. If you know of one, open an issue — we'd love to credit it here.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

---

Built by [IntegSec](https://integsec.com) — our first open-source Rust tool. Found a bug, want a feature, or know a use case we haven't thought of? [Open an issue](https://github.com/IntegSec/PortSnatcher/issues) or [start a discussion](https://github.com/IntegSec/PortSnatcher/discussions) — we want the pentest community shaping this.
