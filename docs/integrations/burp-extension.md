# Burp Suite Extension — v1.1 Roadmap

> **Status:** Deferred to v1.1. Architected-for, not shipped in v1. The `portsnatcher/v1` event schema (see [the design spec](../superpowers/specs/2026-04-22-portsnatcher-design.md), §9) is the stable contract this extension will consume. Any work here is intentionally future-facing.

## Why a first-party extension

The PortSnatcher event bus is general-purpose — any HTTP client can subscribe to `/events` (SSE) or `/events/ws` (WebSocket). A Burp extension turns that generic stream into a **Burp-native workflow**: the moment PortSnatcher catches a port and stands up a hold-open tunnel at `localhost:71xx`, the extension:

1. Adds the tunnel port to Burp's **Target scope** automatically.
2. Injects it as an **upstream proxy mapping** so existing Burp traffic targeting the real remote flows through the tunnel.
3. Surfaces the catch in a new **PortSnatcher tab** with the fingerprint, the raw banner, the TLS info, and a one-click "send to Repeater" using a synthesized request based on the detected protocol.
4. Hot-reloads on `CatchComplete` — the tab stays current as probes refine the fingerprint.

The pentester stays in Burp. PortSnatcher is the sensor; Burp is the cockpit.

## Technical shape

- **Language:** Java (native Montoya API) rather than Jython/BurpExtender to avoid the Python 2.7 tail and stay on a supported API surface.
- **Distribution:** a signed `.jar` on GitHub Releases. Source in this repo under `integrations/burp/` (landing in v1.1).
- **Bus subscription:** WebSocket client to `ws://127.0.0.1:7177/events/ws` with the bearer token read from `~/.config/portsnatcher/bus-token` (same contract as every other consumer).
- **Reconnect:** exponential backoff with a visible state indicator in Burp.
- **No PortSnatcher-side changes:** the extension is a pure consumer of the frozen v1 schema. No `v2` bump is required to add new Burp features.

## Why this waits for v1.1

- The event schema needs to settle under real-world use before we freeze it from two sides. A v1 field rename is trivial during pre-release; after the Burp extension ships, it breaks users' workflows.
- Burp extensions have their own review/packaging overhead that shouldn't block PortSnatcher's core release.
- Caido, ZAP, and custom team integrations will follow the same pattern. Nailing one first-party consumer before cloning it across platforms means the integration shape is proven.

## What v1 must NOT compromise to keep this path open

These are protected by the design spec and will be enforced by CI:

- **Schema stability.** No breaking changes to `portsnatcher/v1` events. Additions only.
- **`catch_id` correlation.** Every catch-related event carries the same `catch_id` so the extension can join `PortOpenDetected` → `HoldOpenReady` → `FingerprintCaptured` without state.
- **Bus auth token contract.** Path and format of `bus-token` must not change.
- **Tunnel endpoint semantics.** `HoldOpenReady.local_port` must always be a local port the extension can point Burp at, regardless of the underlying hold-open mode.

Any PR that touches these surfaces requires explicit review and a version bump before merge.
