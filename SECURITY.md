# Security Policy (`dtnpm-mod-rego-routing`)

## Principles

- **Fail-closed**: in the event of a Rego compilation or evaluation error on an inbound bundle, the Ingress filter drops the bundle (`Verdict::Drop(None)`) to prevent any blacklist bypass.
- **Anti-amplification**: bundles originating from a blacklisted EID are dropped silently (`generate_status_report: false`) to avoid generating return traffic toward a spoofed source.
- **DoS Protection**: CBOR depth limit (`MAX_CBOR_DEPTH = 32`), max custom block size (`256 KiB`), max Rego policy size (`256 KiB`), bounded caches (`seen_cache`, `spray_tracker`, `decision_log`).
- **BPSec Compliance (RFC 9172)**: `RegoEgressRewriter` gracefully handles `ExtensionEditor` refusals on blocks covered by BIB/BCB.

## Reporting a Vulnerability

Report any security vulnerability responsibly to the maintainers of the `dtn-postmaster` project before any public disclosure.
