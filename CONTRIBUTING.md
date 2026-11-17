# Contributing to `dtnpm-mod-rego-routing`

1. Install local Git hooks:
   ```bash
   ./scripts/install-hooks.sh
   ```
2. Follow style conventions (`cargo fmt`) and the zero-`unwrap` policy in `src/`.
3. Add Rego unit tests in `tests/rego_policies_test.rs` and/or Hardy BPA integration tests in `tests/hardy_pipeline_test.rs` for any new rule.
4. Validate the security gate before opening any PR:
   ```bash
   ./scripts/check-security.sh --strict
   cargo test --offline --all-targets
   ```
