# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in PortSnatcher,
please report it privately to **security@integsec.com**. Do not open a
public GitHub issue.

We commit to:

- **Acknowledgement** within 2 business days.
- **Triage and initial assessment** within 5 business days.
- **Fix or mitigation plan** communicated within 14 business days for
  confirmed high/critical-severity issues.
- **Public disclosure** coordinated with the reporter, no earlier than
  30 days after a fix is available unless there is evidence of active
  exploitation.

Please include as much of the following as you can:

- A description of the vulnerability and its impact.
- Reproduction steps (a minimal test case or crafted input is ideal).
- The affected version (output of `portsnatcher --version` is enough).
- Your preferred credit line for the advisory, or an opt-out.

We do not currently operate a paid bug-bounty program. Valid reports
that lead to a published advisory will be credited in the release
notes and the `CHANGELOG.md`.

## PGP / Signed Email

If you need to transmit sensitive details, please request our PGP
key by emailing security@integsec.com. The current public key
fingerprint is published in the repository wiki; see the key in
the repository wiki for the canonical copy. Verify the fingerprint
out of band before encrypting anything sensitive.

## Supported Versions

We support the latest minor release on the main branch. Older
minors receive critical security patches on a best-effort basis
only, and only until the next minor ships.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | Yes                |
| < 1.0   | No                 |

Security patches for supported versions are released as the next
patch increment (e.g. 1.0.1). Release artefacts are signed with
sigstore; verify signatures with `cosign verify-blob` before
installing.

## Out of Scope

The following are explicitly not considered security vulnerabilities
in PortSnatcher:

- Behaviour that results from an operator authorizing PortSnatcher
  to probe a target — by design, an authorized scope permits every
  technique within the authorized techniques list. Scope files are
  the trust boundary, not the network.
- Findings against live internet targets. PortSnatcher is a
  controlled-engagement tool; issues reported about its behaviour on
  arbitrary third-party hosts are not in scope.
- Denial-of-service from pathological configuration (e.g. a rate
  cap so high that local resource exhaustion occurs) unless the
  issue is reachable from a default or documented configuration.
- Issues in pinned dependencies that do not have an upstream fix;
  we will track these via `cargo-deny` but cannot ship patches for
  code we do not own.

## Acknowledgements

Reporters credited in past advisories will be listed here as the
program matures. Until then, thank you in advance for your
responsible disclosure.
