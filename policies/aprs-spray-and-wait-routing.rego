package dtn.routing

import rego.v1

import data.dtn.helpers

# Combined APRS-like + Spray-and-Wait routing policy (Hardy least-privilege).
#
# Priority ordering (lower number = checked first by Hardy's RIB):
#   - Priority 90 : APRS-like `VIA` routes toward authorized IGates / digipeaters
#                   for explicit `aprs_destinations`.
#   - Priority 100: Spray-and-Wait `FORWARD_REPLICATE` routes toward authorized
#                   relays for explicit `snw_destinations`.
#
# Hardy philosophy:
#   - Only explicitly authorized destination patterns and allowed neighbor peers
#     receive routes; unmatched traffic stays in Hardy's `Waiting` state.
#   - Per-bundle APRS trajectory (`ingress.rego`) and Spray-and-Wait quota
#     splitting / Wait-phase enforcement (`egress.rego`) apply automatically.
#
# Usage:
#   1. Customize `aprs_destinations`, `aprs_relays`, `snw_destinations`, and
#      `snw_relays` below.
#   2. Copy this file as `routing.rego` in your `--policy-dir`, OR paste its
#      contents into `rego_routing.custom_routing_rego` (YAML) / the WebUI.

aprs_destinations := {
	"dtn://aprs-igate/**",
}

aprs_relays := {
	"dtn://digipeater-1/",
	"dtn://aprs-igate/",
}

snw_destinations := {
	"dtn://dest-node/**",
	"ipn:0.99.*",
}

# Leave empty (`set()`) to allow any non-blacklisted neighbor peer for SnW.
snw_relays := set()

relay_in_allowlist(peer, allowlist) if {
	count(allowlist) == 0
}

relay_in_allowlist(peer, allowlist) if {
	peer.peer_eid in allowlist
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
	relay_in_allowlist(peer, aprs_relays)
	some pattern in aprs_destinations
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
	relay_in_allowlist(peer, snw_relays)
	some pattern in snw_destinations
}
