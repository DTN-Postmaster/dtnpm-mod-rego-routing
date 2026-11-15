# Contribuer à `dtnpm-mod-rego-routing`

1. Installez les hooks Git locaux :
   ```bash
   ./scripts/install-hooks.sh
   ```
2. Respectez les conventions de style (`cargo fmt`) et la politique zéro-`unwrap` dans `src/`.
3. Ajoutez des tests unitaires Rego dans `tests/rego_policies_test.rs` et/ou d'intégration Hardy BPA dans `tests/hardy_pipeline_test.rs` pour toute nouvelle règle.
4. Validez la porte de sécurité avant toute PR :
   ```bash
   ./scripts/check-security.sh --strict
   cargo test --offline --all-targets
   ```
