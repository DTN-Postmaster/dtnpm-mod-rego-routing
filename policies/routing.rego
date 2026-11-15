package dtn.routing

import rego.v1

import data.dtn.helpers

# Declarative RIB routes driven by neighbor peer changes (input.peers) and
# local node state (input.node, including blacklist_sources).
#
# By default, dtnpm uses static declarative routes + blacklist filtering,
# so no automatic dynamic routes are added here unless overridden via
# --policy-dir, HamConfig.rego_routing, or the WebUI / REST API.
#
# Each entry in `routes` may specify:
#   {
#     "pattern": "dtn://**" | "dtn://node5/**" | "ipn:**",
#     "action": "FORWARD_REPLICATE" | "VIA" | "DROP" | "REFLECT",
#     "next_hop": peer.peer_eid,   # required for VIA / FORWARD_REPLICATE
#     "priority": 100,             # optional, defaults to 100
#     "reason_code": 6             # optional, for DROP
#   }
default routes := []

# Example helper: check whether a neighbor peer is not blacklisted.
peer_allowed(peer) if {
	helpers.peer_allowed(peer, input.node)
}
