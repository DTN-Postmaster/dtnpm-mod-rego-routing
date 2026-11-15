# dtnpm-mod-rego-routing

Module d'extension déclaratif **OPA / Rego** (propulsé par [`regorus`](https://crates.io/crates/regorus)) pour **DTN Postmaster (`dtnpm`)** et **Hardy BPA**.

## Fonctionnalités

- **Filtrage Ingress par liste noire d'EIDs** : correspondance exacte (`dtn://spam/app`) et motifs wildcard (`dtn://spam/*`, `ipn:99.*`), suppression silencieuse sans rapport d'état (anti-amplification) et gestion CRUD temps réel via API REST / WebUI / SQLite.
- **Hop Count Block (Type 10) & Storm Prevention (RFC 9171 §4.3.3 & §5.3 Step 1)** : priorité à la livraison locale (`DELIVER_LOCAL`), vérification conservatrice `(hop_count + 1) >= hop_limit`, cache borné anti-doublon (`seen_cache`) et garde anti-boucle.
- **Fondations Spray-and-Wait & Blocs d'extension custom** :
  - Support du **Bloc Type 200** (`replication_control` issu de `mesh-algo-extension-block.cddl`) et du **Bloc Type 194** (quota `u32` compatible ION-DTN / Hardy `main-dtnpm`).
  - Décodage générique de tout bloc d'extension CBOR inconnu/expérimental vers JSON (`helpers.get_custom_block(input.bundle, block_type)`).
  - Réécriture Egress (`MUTATE_SPRAY_QUOTA` en mode binaire $\lfloor L/2 \rfloor$ ou source) et `RegoRoutingAgent` utilisant `RouteAction::ForwardReplicate` (rétention en stockage Hardy `main-dtnpm`).
- **Routage APRS (Chemin futur) & TREB (Chemin passé)** :
  - **Chemin futur** : Bloc Type 200 `trajectory_control` (`strict_target`, `scoped_alias` ex. `WIDE1-1`, `WIDE2-2`), règles Dire Wolf 6.1(b), 6.2(a), 6.3(a), 6.3(c) et piégeage d'alias excessifs (`WIDE3+`), émission de `route_key`.
  - **Chemin passé (TREB — `draft-koo-dtn-traceroute-eb`)** : bloc expérimental configurable (défaut `201`) consignant les sauts traversés (`node_eid`, `arrival_time_ms`, `departure_time_ms`, `cla_info`) pour l'audit et la détection de boucle (`has_visited_node`).
- **Surcharge utilisateur des politiques Rego** : politiques par défaut embarquées, surcharge par fichiers `.rego` externes (`--policy-dir`) ou édition à chaud via WebUI (`PUT /api/rego_routing/v1/policy`).

## API REST (`/api/rego_routing/v1`)

- `GET /blacklist`, `POST /blacklist`, `PATCH /blacklist/{id}`, `DELETE /blacklist/{id}`
- `GET /policy`, `PUT /policy`
- `GET /decisions`, `POST /decisions/clear`

## Vérification

```bash
./scripts/install-hooks.sh
./scripts/check-security.sh --strict
cargo test --offline --all-targets
```
