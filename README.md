# PortSnatcher

**Catch ephemeral ports the moment they open — fingerprint, hold open, and hand off to the pentester before the window closes.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Status](https://img.shields.io/badge/status-design_complete_%E2%80%94_implementation_in_progress-orange)](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md)
[![Platform](https://img.shields.io/badge/platform-linux_%7C_macOS_%7C_windows-lightgrey)]()
[![Made by IntegSec](https://img.shields.io/badge/made_by-IntegSec-black)](https://integsec.com)

> **Current status — April 2026:** design is locked ([read the spec](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md)); implementation is in progress. This repo is public from day one so the security community can shape the tool as it lands. Install instructions below describe the target UX; replace with "build from source" until the first release ships.

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
[09:14:02] PortSnatcher v0.1.0 — engagement ENG-2026-0142
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

Everything communicates through a versioned JSON event bus. The same stream you see in the TUI is what a webhook receives, what `events.jsonl` records, and what the upcoming Burp extension (v1.1) will subscribe to over HTTP.

## Key features

| | |
|---|---|
| **Two engines, one behavior** | `raw` (userspace TCP via `smoltcp` with per-OS kernel fast-paths on Linux/macOS/Windows) for speed and sub-100ms races; `connect` (unprivileged async `connect()`) for locked-down jumpboxes and containers. Same events, same pipeline. |
| **Probe ladder, not probe list** | Passive banner read first (zero bytes sent), then TLS ClientHello, then port-aware protocol probes — one per fresh connection. Never chains a destructive probe after a soft one. |
| **Hold-open tunnel** | The moment a port is caught, we stand up `localhost:71xx` piping bytes to the target. You point Burp / ncat / your custom exploit at it before the port closes. Optional TLS MITM for HTTPS catches, using a reusable on-disk CA. |
| **Scope-aware probes** | Probes are tagged with [technique categories](https://github.com/IntegSec/agentic-pentest-proxy/blob/master/examples/scope-manifest.json) — `recon`, `web_app`, `api_testing`, `ssl_tls`, `destructive`. Probes without authorized coverage are skipped and audit-logged. |
| **Stable event schema** | `portsnatcher/v1` events are a frozen JSON contract. Additive-only forever. Your Burp extension, SOC pipeline, or custom tooling can depend on it. |
| **Real-time handoff** | Desktop toasts, Slack/Discord/ntfy/PagerDuty webhooks, terminal TUI, SSE/WebSocket bus — all fed from the same stream. |
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

### v1 (target: code-complete over the coming weeks)
- [x] Design locked ([spec](./docs/superpowers/specs/2026-04-22-portsnatcher-design.md))
- [ ] `ps-core` (scope, config, event types)
- [ ] `ps-engine` (raw + connect)
- [ ] `ps-fingerprint` (probe ladder + v1 probe registry)
- [ ] `ps-proxy` (dumb tunnel + TLS MITM)
- [ ] `ps-bus` (SSE + WebSocket + frozen `portsnatcher/v1` schema)
- [ ] `ps-notify` (terminal + TUI + toast + webhooks)
- [ ] Cross-platform CI (Linux / macOS / Windows)
- [ ] Race-harness conformance tests with codified catch-rate gates
- [ ] First public release on crates.io and GitHub Releases

### v1.1
- First-party **Burp Suite extension** (Montoya API) that subscribes to the event bus and auto-wires caught tunnels into Burp's upstream
- Caido / ZAP plugins following the same pattern
- Web dashboard for the event bus
- IPv6 support

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
| `RawEngine` (userspace `smoltcp`) | yes | yes | yes |
| `RawEngine` kernel fast-path | `nftables` | `pf` | `WinDivert` |
| Requires elevation for `RawEngine` | `CAP_NET_RAW` | root / `ChmodBPF` | admin |

Full feature parity across all three OSes is a v1 acceptance criterion — not a v1.1 goal.

## Building from source (during pre-release development)

```bash
git clone https://github.com/IntegSec/PortSnatcher
cd PortSnatcher
cargo build --release
./target/release/portsnatcher --help
```

Once released:
```bash
cargo install integsec-portsnatcher
```

Or grab a signed prebuilt from [Releases](https://github.com/IntegSec/PortSnatcher/releases).

## Contributing

PortSnatcher is open to community contributions, but the event-bus schema and scope-file format are **stability-critical** — breaking changes require explicit discussion and a version bump. See `CONTRIBUTING.md` (landing alongside v0.1) for the process. For security-sensitive reports, see `SECURITY.md`.

## Prior art and influences

PortSnatcher stands on the shoulders of:
- `nmap`, `masscan`, `zmap`, `unicornscan` — port-scanning state of the art
- `smoltcp` — the userspace TCP/IP stack that makes the `RawEngine` portable
- `rustls` — the TLS implementation used throughout
- `ratatui`, `tokio`, `axum` — Rust's superb async ecosystem
- Burp Collaborator / Interactsh — prior art for out-of-band handoff patterns
- IntegSec's [`agentic-pentest-proxy`](https://github.com/IntegSec/agentic-pentest-proxy) — sister tool and source of the scope-file format

We are not aware of any prior tool combining continuous SYN-level racing, short-window fingerprinting on fresh connections, and pentester-in-the-loop hold-open handoff in one package. If you know of one, open an issue — we'd love to credit it here.

## License

Apache License 2.0 — see [`LICENSE`](./LICENSE) and [`NOTICE`](./NOTICE).

---

Made in Canada by [IntegSec](https://integsec.com) — our first open-source Rust tool.
