package dtn.egress

import rego.v1

import data.dtn.constants
import data.dtn.helpers

default decision := {
	"action": "FORWARD",
	"reason": "Default egress forward",
	"mutations": [],
}

treb_departure_mutations := [
	{
		"block_type": helpers.treb_block_type(input.node),
		"operation": "APPEND_TREB_DEPARTURE",
		"field": "hops",
		"value": {
			"node_eid": input.node.local_eid,
			"departure_time_ms": input.current_dtn_time_ms,
			"cla_info": object.get(input.contact, "cla_type", "bpa"),
		},
	},
] if {
	helpers.has_treb_block(input.bundle, input.node)
} else := [
	{
		"block_type": helpers.treb_block_type(input.node),
		"operation": "APPEND_TREB_DEPARTURE",
		"field": "hops",
		"value": {
			"node_eid": input.node.local_eid,
			"departure_time_ms": input.current_dtn_time_ms,
			"cla_info": object.get(input.contact, "cla_type", "bpa"),
		},
	},
] if {
	object.get(input.node, "record_treb", false) == true
} else := []

peer_is_destination if {
	input.contact.is_broadcast != true
	input.contact.peer_eid == input.bundle.primary.destination
}

split_horizon_skip if {
	not peer_is_destination
	helpers.is_from_peer(input.bundle, input.contact.peer_eid)
}

split_horizon_skip if {
	not peer_is_destination
	helpers.has_visited_node(input.bundle, input.node, input.contact.peer_eid)
}

hop_limit_drop if {
	not peer_is_destination
	not split_horizon_skip
	helpers.is_hop_limit_reached(input.bundle)
}

spray_wait_active if {
	not peer_is_destination
	not split_horizon_skip
	not hop_limit_drop
	helpers.has_spray_block(input.bundle)
}

spray_peer_holds if {
	spray_wait_active
	held := object.get(input.contact, "held_bundle_ids", [])
	cid := helpers.canonical_bundle_id(input.bundle)
	cid in held
}

# 1. Direct delivery to final destination contact.
decision := {
	"action": "FORWARD_DIRECT",
	"reason": "Next hop is the final bundle destination",
	"mutations": treb_departure_mutations,
} if {
	peer_is_destination
}

# 2. Split-horizon / TREB loop guard: do not reflect bundle back to previous or visited hop.
decision := {
	"action": "SKIP",
	"reason": "Peer is previous sender or already recorded in TREB past path",
	"mutations": [],
} if {
	split_horizon_skip
}

# 3. Hop count exhausted at egress.
decision := {
	"action": "DROP",
	"reason": "Hop limit reached at egress",
	"mutations": [],
} if {
	hop_limit_drop
}

# 4. Spray-and-Wait: peer already holds a copy in its summary vector.
decision := {
	"action": "SKIP",
	"reason": "Peer already holds bundle copy",
	"mutations": [],
} if {
	spray_wait_active
	spray_peer_holds
}

# 5. Spray-and-Wait: WAIT phase (quota L <= 1).
decision := {
	"action": "SKIP",
	"reason": "Spray-and-Wait WAIT phase (quota <= 1): direct destination delivery only",
	"mutations": [],
} if {
	spray_wait_active
	not spray_peer_holds
	quota := helpers.get_spray_quota(input.bundle)
	quota <= 1
}

# 6. Spray-and-Wait: SPRAY phase binary mode (L >= 2).
decision := {
	"action": "FORWARD_REPLICATE",
	"reason": sprintf("Binary Spray-and-Wait: splitting L=%d -> tx=%d, keep=%d", [quota, split.send_quota, split.keep_quota]),
	"mutations": array.concat(
		[{
			"block_type": spray_block_type(input.bundle),
			"operation": "MUTATE_SPRAY_QUOTA",
			"local_quota": split.keep_quota,
			"local_phase": split.new_local_phase,
			"transmitted_quota": split.send_quota,
			"transmitted_phase": split.transmitted_phase,
		}],
		treb_departure_mutations,
	),
} if {
	spray_wait_active
	not spray_peer_holds
	quota := helpers.get_spray_quota(input.bundle)
	quota >= 2
	helpers.get_spray_mode(input.bundle) == constants.spray_mode_binary
	split := helpers.calculate_binary_spray(quota)
}

# 7. Spray-and-Wait: SPRAY phase source mode (L >= 2).
decision := {
	"action": "FORWARD_REPLICATE",
	"reason": sprintf("Source Spray-and-Wait: tx=1, keep=%d", [quota - 1]),
	"mutations": array.concat(
		[{
			"block_type": spray_block_type(input.bundle),
			"operation": "MUTATE_SPRAY_QUOTA",
			"local_quota": quota - 1,
			"local_phase": helpers.phase_for_quota(quota - 1),
			"transmitted_quota": 1,
			"transmitted_phase": constants.spray_phase_wait,
		}],
		treb_departure_mutations,
	),
} if {
	spray_wait_active
	not spray_peer_holds
	quota := helpers.get_spray_quota(input.bundle)
	quota >= 2
	helpers.get_spray_mode(input.bundle) == constants.spray_mode_source
}

spray_block_type(bundle) := constants.block_type_mesh_routing if {
	helpers.mesh_has_replication(bundle)
} else := constants.block_type_spray_permit

# 8. APRS broadcast or unicast forwarding.
decision := {
	"action": "FORWARD_BROADCAST",
	"reason": "APRS broadcast transmission",
	"mutations": treb_departure_mutations,
} if {
	not peer_is_destination
	not split_horizon_skip
	not hop_limit_drop
	not spray_wait_active
	helpers.has_aprs_trajectory(input.bundle)
	input.contact.is_broadcast == true
}

decision := {
	"action": "FORWARD_UNICAST",
	"reason": "APRS unicast forwarding",
	"mutations": treb_departure_mutations,
} if {
	not peer_is_destination
	not split_horizon_skip
	not hop_limit_drop
	not spray_wait_active
	helpers.has_aprs_trajectory(input.bundle)
	input.contact.is_broadcast != true
}

# 9. Standard forwarding with optional TREB departure update.
decision := {
	"action": "FORWARD",
	"reason": "Standard BPv7 egress forwarding",
	"mutations": treb_departure_mutations,
} if {
	not peer_is_destination
	not split_horizon_skip
	not hop_limit_drop
	not spray_wait_active
	not helpers.has_aprs_trajectory(input.bundle)
}
