# AGENTS.md — `dtnpm-mod-rego-routing`

Consignes de développement et de sécurité applicables à ce dépôt :

1. **Architecture & Découplage** :
   - Toute logique de décision de filtrage ou de routage (blacklist, hop limit, storm, Spray-and-Wait, APRS, TREB) doit rester déclarative dans `policies/*.rego` et compilée via `regorus`.
   - Aucune dépendance réseau au runtime pour les politiques Rego ; le moteur fonctionne 100 % hors-ligne.
2. **Hygiène Rust & CRA (Cyber Resilience Act)** :
   - Zéro `.unwrap()`, `.expect()`, `panic!()` ou `todo!()` dans `src/` (vérifié par `cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::panic`).
   - Validation stricte de toutes les entrées utilisateur (motifs EID ≤ 256 octets ASCII imprimables avec schéma URI BPv7, taille des politiques Rego ≤ 256 KiB, profondeur CBOR ≤ 32, plage expérimentale TREB `192..=255`).
   - Les caches en mémoire (`seen_cache`, `spray_tracker`, `decision_log`) doivent rester strictement bornés.
   - Les erreurs d'`ExtensionEditor` (par ex. bloc protégé par BPSec BIB/BCB) doivent être journalisées sans interrompre le BPA.
3. **PBAC / IAM** :
   - Les opérations d'écriture sur `/blacklist` et `/policy` doivent rester réservées au rôle `Admin` dans `dtnpm-core/src/iam/default_policy.rego`.
4. **Qualité avant commit** :
   - Exécuter `cargo fmt --all -- --check`, `./scripts/check-security.sh --strict` et `cargo test --offline --all-targets`.
