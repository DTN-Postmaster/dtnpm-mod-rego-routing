# ADR-0001 : Moteur de routage déclaratif OPA/Rego et blocs d'extension BPv7

- **Statut** : Accepté
- **Date** : 2026-11-15

## Contexte

L'écosystème `dtn-postmaster` nécessite de supporter plusieurs algorithmes de routage et de filtrage (blacklist Ingress, Hop Count RFC 9171 §4.3.3, Spray-and-Wait, routage APRS à chemin futur et traçage TREB passé) sans figer les règles métier dans du code Rust recompilé à chaque ajustement opérationnel.

## Décision

1. **Moteur Rego embarqué (`regorus`)** : toutes les règles de décision sont exprimées en Rego (`policies/{dtn_constants,helpers,ingress,egress}.rego`), avec possibilité de surcharge par fichiers externes (`--policy-dir`) ou à chaud via SQLite/WebUI (`PUT /api/rego_routing/v1/policy`).
2. **Intégration Hardy BPA via `FilterPack` + `WebModule::filter_packs()`** :
   - `RegoIngressVerifier` et `RegoIngressClassifier` exécutent `data.dtn.ingress.decision`, stockent les mutations différées et `route_key` dans le slot `REGO_BUNDLE_DECISION` (`hardy_bpa::slot!`).
   - `RegoEgressRewriter` exécute `data.dtn.egress.decision` au passage `Boundary::Egress` et applique les mutations sur les blocs via `ExtensionEditor`. L'incrément filaire du bloc Hop Count (Type 10) est laissé à `hardy_bpa::dispatcher::forward::update_extension_blocks` pour éviter un double incrément.
   - `RegoRoutingAgent` implémente `hardy_bpa::routing::RoutingAgent` et fournit des helpers (`add_spray_route`, `remove_spray_route`) prêts pour la branche `feat/spray-n-wait` de Hardy.
3. **Format des blocs d'extension** :
   - **Type 200 (`MeshRoutingData`)** : conforme à `mesh-algo-extension-block.cddl` (clés entières compactes 1..6 ; pour `scoped-alias`, la clé entière `5` porte `completed` afin de lever le recouvrement avec la clé `3` `max-count`, tout en acceptant les deux formes au décodage).
   - **Type 194 (`SprayPermit`)** : entier `u32` CBOR simple assurant l'interopérabilité directe avec ION-DTN et Hardy `feat/spray-n-wait`.
   - **Type 201 configurable (`TrebData`)** : chemin passé conforme à `draft-koo-dtn-traceroute-eb` (`node_eid`, `arrival_time_ms`, `departure_time_ms`, `cla_info`).
   - **Blocs custom arbitraires** : tout autre bloc expérimental CBOR est décodé récursivement (profondeur max 32) en JSON pour être inspectable depuis Rego via `helpers.get_custom_block`.

## Conséquences

- Les opérateurs/administrateurs peuvent bloquer des EIDs et adapter les politiques de routage à chaud sans redémarrer ni recompiler `dtnpm`.
- Les opérations d'écriture REST (`/blacklist`, `/policy`) restent restreintes au rôle `Admin` via le PBAC de `dtnpm-core`.
