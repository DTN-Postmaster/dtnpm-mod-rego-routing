# ADR-0001: Declarative OPA/Rego Routing Engine and BPv7 Extension Blocks

- **Status**: Accepted
- **Date**: 2026-11-15

## Context

The `dtn-postmaster` ecosystem needs to support multiple routing and filtering algorithms (Ingress blacklist, Hop Count RFC 9171 §4.3.3, Spray-and-Wait, future-path APRS routing, and past-path TREB tracing) without hardcoding business rules in Rust code that must be recompiled for every operational adjustment.

## Decision

1. **Embedded Rego Engine (`regorus`)**: all decision rules are expressed in Rego (`policies/{dtn_constants,helpers,ingress,egress}.rego`), with support for overrides via external files (`--policy-dir`) or hot-reloading via SQLite/WebUI (`PUT /api/rego_routing/v1/policy`).
2. **Hardy BPA Integration via `FilterPack` + `WebModule::filter_packs()`**:
   - `RegoIngressVerifier` and `RegoIngressClassifier` execute `data.dtn.ingress.decision`, storing deferred mutations and `route_key` in the `REGO_BUNDLE_DECISION` slot (`hardy_bpa::slot!`).
   - `RegoEgressRewriter` executes `data.dtn.egress.decision` at `Boundary::Egress` and applies block mutations via `ExtensionEditor`. Wire-level incrementing of the Hop Count block (Type 10) is left to `hardy_bpa::dispatcher::forward::update_extension_blocks` to avoid double-incrementing.
   - `RegoRoutingAgent` implements `hardy_bpa::routing::RoutingAgent` and provides helpers (`add_spray_route`, `add_spray_route_for_bundle`, `remove_spray_route`) built on Hardy's `RouteAction::ForwardReplicate` (`loic-fejoz/hardy`, `main-dtnpm` branch).
3. **Extension Block Formats**:
   - **Type 200 (`MeshRoutingData`)**: conforms to `mesh-algo-extension-block.cddl` (compact integer keys 1..6; for `scoped-alias`, integer key `5` carries `completed` to resolve the overlap with key `3` `max-count`, while accepting both forms when decoding).
   - **Type 194 (`SprayPermit`)**: simple CBOR `u32` integer ensuring direct interoperability with ION-DTN and Hardy `main-dtnpm`.
   - **Configurable Type 201 (`TrebData`)**: past path conforming to `draft-koo-dtn-traceroute-eb` (`node_eid`, `arrival_time_ms`, `departure_time_ms`, `cla_info`).
   - **Arbitrary custom blocks**: any other experimental CBOR block is recursively decoded (max depth 32) into JSON so it can be inspected from Rego via `helpers.get_custom_block`.

## Consequences

- Operators and administrators can block EIDs and adapt routing policies at runtime without restarting or recompiling `dtnpm`.
- REST write operations (`/blacklist`, `/policy`) remain restricted to the `Admin` role via `dtnpm-core` PBAC.
