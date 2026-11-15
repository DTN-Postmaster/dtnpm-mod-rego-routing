package dtn.routing

import rego.v1

import data.dtn.helpers

# Spray-and-Wait-only routing policy (Hardy least-privilege / Default-to-Wait).
#
# Hardy philosophy (see hardy/docs/user-docs/configuration/bpa-server.md and
# hardy/bpa/docs/routing_subsystem_design.md):
#   - Only install routes for explicitly authorized destination patterns and
#     allowed neighbor peers.
#   - Do NOT install blanket catch-all wildcards (`dtn://**`, `ipn:**`) toward
#     arbitrary peers: unmatched bundles remain in Hardy's `Waiting` state
#     until an authorized route appears, and unregistered local services are not
#     hijacked by catch-all forwarding rules.
#   - Quota splitting (`L -> tx, keep`) and Wait-phase (`L <= 1`) enforcement
#     are handled by `egress.rego`.
#
# Usage:
#   1. Customize `allowed_destinations` (and optionally `allowed_relays`) below
#      for the destination EID patterns and relay peers permitted in your network.
#   2. Copy this file as `routing.rego` in your `--policy-dir`, OR paste its
#      contents into `rego_routing.custom_routing_rego` (YAML) / the WebUI.

# Explicitly authorized destination EID patterns for Spray-and-Wait replication.
# Replace with the destination patterns your node is authorized to relay toward.
allowed_destinations := {
	"dtn://dest-node/**",
	"ipn:0.99.*",
}

# Optional relay allowlist. Leave empty (`set()`) to allow any non-blacklisted
# neighbor peer, or list specific relay EIDs (e.g. `{"dtn://relay-1/"}`).
allowed_relays := set()

relay_authorized(peer) if {
	count(allowed_relays) == 0
}

relay_authorized(peer) if {
	peer.peer_eid in allowed_relays
}

routes contains {
	"pattern": pattern,
	"action": "FORWARD_REPLICATE",
	"next_hop": peer.peer_eid,
	"priority": 100,
} if {
	some peer in input.peers
	helpers.peer_allowed(peer, input.node)
	not helpers.is_local_destination(peer.peer_eid, input.node)
	relay_authorized(peer)
	some pattern in allowed_destinations
}
