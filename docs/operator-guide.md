# PortSnatcher Operator Guide

This guide walks through a full PortSnatcher engagement end to end:
install, scope-file authoring, engagement setup, live scanning,
reading the terminal UI, attaching Burp through a hold-open tunnel,
standing up TLS MITM, and cleaning up when you are done.

PortSnatcher is a short-window port catcher designed for authorized
engagements. Every outbound packet is gated behind a `ScopeGuard` so
you cannot accidentally probe something the scope file does not
authorize. Keep that mental model in mind — "did I authorize this?"
is the question the tool asks before every connect.

---

## Installing

PortSnatcher ships as a single static binary per platform. Download
the release artifact for your OS and architecture from the GitHub
Releases page and verify the sigstore signature before running it:

```bash
cosign verify-blob \
  --certificate portsnatcher-x86_64-unknown-linux-gnu.tar.gz.pem \
  --signature portsnatcher-x86_64-unknown-linux-gnu.tar.gz.sig \
  --certificate-identity-regexp '^https://github.com/IntegSec/PortSnatcher/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  portsnatcher-x86_64-unknown-linux-gnu.tar.gz
```

Unpack the archive and move `portsnatcher` into your `$PATH`. On
Linux you can optionally grant `CAP_NET_RAW` to enable the raw
engine without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which portsnatcher)
```

On macOS, raw-socket support requires elevated privileges via `sudo`
for now; on Windows, run the binary from an Administrator shell.

Verify the installation:

```bash
portsnatcher --version
portsnatcher --help
```

If you plan to build from source, install the `rust-toolchain.toml`
pinned toolchain and run `cargo build --release -p
integsec-portsnatcher`. Release builds turn on link-time optimization
and strip debug info, so the binary should match the shipped artifact
in size to within a few percent.

---

## Authoring a scope file

PortSnatcher consumes the scope-file schema owned by
[IntegSec/agentic-pentest-proxy](https://github.com/IntegSec/agentic-pentest-proxy).
The minimum viable scope file looks like this:

```json
{
  "engagement_id": "acme-q2-internal",
  "client": "Acme Corp",
  "operator": "alice@integsec.com",
  "authorized_targets": {
    "ip_ranges": ["10.20.30.0/24"],
    "domains": [],
    "urls": [],
    "cloud_accounts": []
  },
  "excluded_targets": ["10.20.30.99"],
  "authorized_techniques": ["recon", "webapp"],
  "excluded_techniques": ["destructive"],
  "engagement_window": {
    "start": "2026-04-22T00:00:00Z",
    "end":   "2026-05-22T00:00:00Z"
  },
  "portsnatcher": {
    "port_policy": {
      "include": ["ephemeral-iana"],
      "exclude": ["49200-49299"]
    }
  }
}
```

The PortSnatcher extension is optional. If present, `port_policy`
constrains which TCP ports we will probe — common values for
`include` are `"ephemeral-iana"` (49152-65535), `"registered"` (1024-49151),
or an explicit `"80,443,8080,8443"`-style list. `exclude` is
evaluated after `include` and always wins.

Load the file and validate without probing:

```bash
portsnatcher validate --scope ./scope.json
```

Validation checks the JSON shape, parses the engagement window,
confirms at least one authorized range exists, and prints the
resolved `ScopeGuard` so you can eyeball the CIDR allowlist.

---

## Setting up the engagement

A PortSnatcher engagement is the combination of a scope file, a
runtime config, and a profile (`internal`, `external`, `cloud`). The
profile picks sensible defaults for timeouts, retry budgets, and
rate caps — you can override any of them in the config file.

A minimal `portsnatcher.toml`:

```toml
# Where engagement artefacts (events, fingerprint cache, pcaps) land.
artifacts_dir = "./artifacts"

# Scope file consumed at start.
scope_file = "./scope.json"

# Profile overrides.
[profile.internal]
rate_cap_pps = 50000
connect_timeout_ms = 800
hold_open_timeout_s = 900
```

Start a dry run to confirm wiring and ScopeGuard resolution without
touching the network:

```bash
portsnatcher run \
  --config ./portsnatcher.toml \
  --engine connect \
  --profile internal \
  --dry-run
```

Dry runs emit every event the real run would emit except the ones
that would require an actual socket. The audit log, scope violations,
and the `EngagementStarted` / `EngagementFinished` bookends all
appear; use this to smoke-test configuration changes before burning
real time.

---

## Running a live scan

Remove `--dry-run` when you are ready to go:

```bash
portsnatcher run \
  --config ./portsnatcher.toml \
  --engine connect \
  --profile internal
```

If stdout is a terminal, the TUI starts automatically. Force-disable
it with `--no-tui` (useful when piping to `grep` or `jq`); force-enable
with `--tui` (useful when your terminal isn't detected as one).

Each `PortOpenDetected` spawns a hold-open tunnel on a local port in
the 7101-7199 range. That tunnel stays up until the upstream closes
the connection or `hold_open_timeout_s` elapses. Meanwhile the
fingerprinter walks its probe ladder (passive banner, HTTP HEAD, TLS
ClientHello, Redis PING, and so on) and records what it finds under
`artifacts/<engagement-id>/catches/<catch-id>/`.

To stop early, press `q` in the TUI or send `SIGINT`. Either way the
orchestrator drains in-flight work, emits `EngagementFinished`, and
flushes the fingerprint cache before exiting.

---

## Reading the TUI

The TUI divides the screen into four panels.

**Catches** (top-left). Every caught port shows up here as a row with
target, engine, detected protocol, confidence score, tunnel port, and
status. Status is color-coded: yellow `detecting` means the
fingerprinter hasn't weighed in yet, green `holding` means the
hold-open tunnel is live, gray `done` means the catch has completed.
Use `Up`/`Down` to move the selection cursor.

**Holds** (top-right). Every active hold-open tunnel, keyed by local
port. This is the source of truth for where to point your browser or
proxy.

**Rate gauge** (bottom-left). Current pps versus configured cap,
plus a running audit count. The gauge turns fully red when you are
within 5% of the cap — that is the orchestrator's signal that it is
throttling, which means some catches will be missed.

**Event log** (bottom-right). A color-coded tail of the last fifty
events. Green for port opens, red for scope-violation audit lines,
yellow for rate-cap engagement, cyan for hold-open ready, gray for
hold-open closed. Press `p` to pause auto-scroll; press `c` to clear
completed catches from the Catches panel.

Press `Enter` on a selected row to copy `localhost:<tunnel_port>` to
the system clipboard. That address is what you paste into Burp's
upstream-proxy config or curl one-liners.

---

## Attaching Burp to a hold-open tunnel

PortSnatcher's default hold-open mode is `dumb_tunnel`: bidirectional
bytes with no inspection, which is what you want if the upstream
already speaks HTTP and you want Burp to see raw traffic.

1. In Burp, open **User options → Upstream Proxy Servers** and add a
   rule: destination host `*`, proxy host `localhost`, proxy port
   `<tunnel_port>` (the value from the Holds panel).
2. Alternatively, skip upstream proxying entirely and point Burp's
   target at `http://localhost:<tunnel_port>/`. PortSnatcher relays
   every byte to the real upstream unmodified.
3. Open Burp's Proxy → Options → Intercept or use the Repeater tab.
   Request/response pairs should flow through as if you were talking
   to the upstream directly.

For scripted clients, set the `HTTPS_PROXY=http://localhost:8080`
(or whatever Burp listens on) and let Burp forward through the
PortSnatcher tunnel:

```bash
HTTPS_PROXY=http://localhost:8080 curl -v http://localhost:<tunnel_port>/
```

Hold-open tunnels honor the engagement window and the `ScopeGuard`
at the moment they open. If the scope expires mid-session, existing
tunnels remain up — the scope only gates probe initiation.

---

## TLS MITM setup

For catches that speak TLS, switch hold-open into `tls_mitm` mode to
get plaintext capture. PortSnatcher generates a short-lived CA on
first run (stored under `artifacts/<engagement>/ca/`) and signs a
leaf for every upstream server-name observed via SNI.

Enable MITM per catch via the hold-open mode override in your config:

```toml
[hold_open]
mode = "tls_mitm"
```

Before Burp will accept the MITM certs, you must trust the generated
CA. PortSnatcher prints the CA fingerprint in the `HoldOpenReady`
event and writes the cert to `artifacts/<engagement>/ca/ca.pem`.

- **Burp**: Proxy → Options → Import/Export CA certificate → Import a
  certificate in DER or PEM format.
- **System trust store (Linux)**: `sudo cp ca.pem /usr/local/share/ca-certificates/portsnatcher-<engagement>.crt && sudo update-ca-certificates`.
- **System trust store (macOS)**: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem`.

After MITM is trusted, every TLS byte flowing through the tunnel is
re-encrypted to Burp's listener and logged to
`artifacts/<engagement>/catches/<catch>/tls/`. The
`FingerprintCaptured` event includes a `tls_info` record with the
observed SNI, ALPN, cert subject, issuer, and expiry.

---

## Cleaning up

At the end of the engagement:

1. Press `q` in the TUI (or `Ctrl-C`) to stop the orchestrator.
   Wait for `EngagementFinished` to print — that event confirms the
   fingerprint cache has been flushed and every hold-open tunnel
   has been torn down.
2. Run `portsnatcher cleanup --engagement <id>`. This removes any
   firewall rules inserted for raw-engine shaping, releases stale
   tunnel ports, and (optionally, with `--wipe`) deletes the
   per-catch MITM CA so it cannot be reused.
3. If you loaded the MITM CA into a system trust store, remove it:
   - Linux: `sudo rm /usr/local/share/ca-certificates/portsnatcher-<engagement>.crt && sudo update-ca-certificates --fresh`.
   - macOS: `sudo security delete-certificate -c "PortSnatcher <engagement>" /Library/Keychains/System.keychain`.
   - Browser trust stores (Burp, Firefox) — remove via their UIs.
4. Archive `artifacts/<engagement-id>/` according to your engagement
   retention policy. The directory is self-contained: events (jsonl),
   fingerprint cache (json), probe artefacts (pcap/pem), and the
   ScopeGuard audit log.

That is the complete loop: install, scope, run, read, inspect,
cleanup. For deeper details — event schema, scope-guard semantics,
the probe ladder, the race-harness thresholds — see
`docs/superpowers/specs/2026-04-22-portsnatcher-design.md`.
