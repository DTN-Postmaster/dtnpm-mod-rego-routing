# Politique de Sécurité (`dtnpm-mod-rego-routing`)

## Principes

- **Fail-closed** : en cas d'erreur de compilation ou d'évaluation Rego sur un bundle entrant, le filtre Ingress rejette le bundle (`Verdict::Drop(None)`) afin d'éviter tout contournement de liste noire.
- **Anti-amplification** : les bundles issus d'un EID blacklisté sont rejetés silencieusement (`generate_status_report: false`) pour ne pas générer de trafic de retour vers une source usurpée.
- **Protection DoS** : limitation de profondeur CBOR (`MAX_CBOR_DEPTH = 32`), taille max de bloc custom (`256 KiB`), taille max de politique Rego (`256 KiB`), caches bornés (`seen_cache`, `spray_tracker`, `decision_log`).
- **Conformité BPSec (RFC 9172)** : `RegoEgressRewriter` gère gracieusement les refus d'`ExtensionEditor` sur les blocs couverts par BIB/BCB.

## Signalement de vulnérabilité

Signalez toute vulnérabilité de sécurité de manière responsable aux mainteneurs du projet `dtn-postmaster` avant toute divulgation publique.
