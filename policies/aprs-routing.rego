package dtn.routing

import rego.v1

import data.dtn.helpers

# APRS-like routing policy (Hardy least-privilege / Default-to-Wait).
#
# Hardy philosophy:
#   - Only install `VIA` routes for explicitly authorized APRS destinations
#     (e.g., IGates or APRS services) and authorized neighbor relays/digipeaters.
#   - Unmatched destinations remain in Hardy's `Waiting` state until a route
#     appears; blacklisted peers are excluded via `helpers.peer_allowed`.
#   - Per-bundle APRS trajectory handling (WIDE1/WIDE2 alias decrement, strict
#     hop progression via `route_key`, loop/trap drop, TREB, broadcast/unicast)
#     remains enforced by `ingress.rego` and `egress.rego`.
#
# Usage:
#   1. Customize `aprs_destinations` and `aprs_relays` below.
#   2. Copy this file as `routing.rego` in your `--policy-dir`, OR paste its
#      contents into `rego_routing.custom_routing_rego` (YAML) / the WebUI.

# Explicitly authorized APRS destination EID patterns.
aprs_destinations := {
	"dtn://aprs-igate/**",
}

# Authorized APRS neighbor relays / digipeaters / IGates.
# Leave empty (`set()`) to allow any non-blacklisted neighbor peer, or list
# specific relay EIDs.
aprs_relays := {
	"dtn://digipeater-1/",
	"dtn://aprs-igate/",
}

aprs_relay_authorized(peer) if {
	count(aprs_relays) == 0
}

aprs_relay_authorized(peer) if {
	peer.peer_eid in aprs_relays
}

routes contains {
	"pattern": pattern,
	"action": "VIA",
	"next_hop": peer.peer_eid,
	"priority": 90,
} if {
	some peer in input.peers
	helpers.peer_allowed(peer, input.node)
	not helpers.is_local_destination(peer.peer_eid, input.node)
	aprs_relay_authorized(peer)
	some pattern in aprs_destinations
}
