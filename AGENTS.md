# AGENTS.md — `dtnpm-mod-rego-routing`

Development and security guidelines for this repository:

1. **Documentation Language**:
   - English must be used as the language for all documentation, unless the file is suffixed with `.fr.md` or another language is explicitly requested in the prompt.
2. **Architecture & Decoupling**:
   - All filtering or routing decision logic (blacklist, hop limit, storm, Spray-and-Wait, APRS, TREB) must remain declarative in `policies/*.rego` and compiled via `regorus`.
   - No runtime network dependencies for Rego policies; the engine operates 100% offline.
3. **Rust Hygiene & CRA (Cyber Resilience Act)**:
   - Zero `.unwrap()`, `.expect()`, `panic!()`, or `todo!()` in `src/` (enforced by `cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::panic`).
   - Strict validation of all user inputs (EID patterns <= 256 printable ASCII bytes with BPv7 URI scheme, Rego policy size <= 256 KiB, CBOR depth <= 32, TREB experimental range `192..=255`).
   - In-memory caches (`seen_cache`, `spray_tracker`, `decision_log`) must remain strictly bounded.
   - `ExtensionEditor` errors (e.g., block protected by BPSec BIB/BCB) must be logged without interrupting the BPA.
4. **PBAC / IAM**:
   - Write operations on `/blacklist` and `/policy` must remain restricted to the `Admin` role in `dtnpm-core/src/iam/default_policy.rego`.
5. **Pre-commit Quality**:
   - Run `cargo fmt --all -- --check`, `./scripts/check-security.sh --strict`, and `cargo test --offline --all-targets`.
