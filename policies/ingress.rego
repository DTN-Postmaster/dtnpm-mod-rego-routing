package dtn.ingress

import rego.v1

import data.dtn.constants
import data.dtn.helpers

default decision := {
	"action": "DROP",
	"reason_code": 6,
	"reason": "Default drop rule",
	"generate_status_report": false,
	"route_key": null,
	"mutations": [],
}

deny_blacklist if {
	helpers.is_source_blacklisted(input.bundle.primary.source, input.node)
}

is_local_dest if {
	not deny_blacklist
	helpers.is_local_destination(input.bundle.primary.destination, input.node)
}

deny_expired if {
	not deny_blacklist
	not is_local_dest
	helpers.is_lifetime_expired(input.bundle, input.current_dtn_time_ms)
}

deny_hop_limit if {
	not deny_blacklist
	not is_local_dest
	not deny_expired
	helpers.will_exceed_hop_limit(input.bundle)
}

deny_storm if {
	not deny_blacklist
	not is_local_dest
	not deny_expired
	not deny_hop_limit
	helpers.is_storm_or_loop(input.bundle, input.node)
}

transit_allowed if {
	not deny_blacklist
	not is_local_dest
	not deny_expired
	not deny_hop_limit
	not deny_storm
}

# Compute mutations triggered at ingress (hop count increment, APRS future hop consumption, TREB arrival).
hop_count_mutations := [
	{
		"block_type": constants.block_type_hop_count,
		"operation": "SET_FIELD",
		"field": "hop_count",
		"value": hcb.hop_count + 1,
	},
] if {
	hcb := helpers.get_hop_count_block(input.bundle)
} else := []

treb_mutations := [
	{
		"block_type": helpers.treb_block_type(input.node),
		"operation": "APPEND_TREB_HOP",
		"field": "hops",
		"value": {
			"node_eid": input.node.local_eid,
			"arrival_time_ms": input.current_dtn_time_ms,
		},
	},
] if {
	helpers.has_treb_block(input.bundle, input.node)
} else := [
	{
		"block_type": helpers.treb_block_type(input.node),
		"operation": "APPEND_TREB_HOP",
		"field": "hops",
		"value": {
			"node_eid": input.node.local_eid,
			"arrival_time_ms": input.current_dtn_time_ms,
		},
	},
] if {
	object.get(input.node, "record_treb", false) == true
} else := []

# 0. Blacklist filter: silent drop without generating any status report (anti-amplification).
decision := {
	"action": "DROP",
	"reason_code": constants.reason_depleted_storage,
	"reason": "Source EID is blacklisted on this node",
	"generate_status_report": false,
	"route_key": null,
	"mutations": [],
} if {
	deny_blacklist
}

# 1. Local delivery takes priority over transit hop count (RFC 9171 §5.3 Step 1).
decision := {
	"action": "DELIVER_LOCAL",
	"reason": "Destination endpoint matches local node",
	"generate_status_report": false,
	"route_key": null,
	"mutations": [],
} if {
	is_local_dest
}

# 2. Bundle lifetime expiration on arrival.
decision := {
	"action": "DROP",
	"reason_code": constants.reason_lifetime_expired,
	"reason": "Bundle lifetime expired upon arrival",
	"generate_status_report": helpers.is_deletion_report_requested(input.bundle),
	"route_key": null,
	"mutations": [],
} if {
	deny_expired
}

# 3. Hop Count Block (Type 10) limit exceeded (RFC 9171 §4.3.3).
decision := {
	"action": "DROP",
	"reason_code": constants.reason_hop_limit_exceeded,
	"reason": "Hop limit exceeded after ingress hop increment",
	"generate_status_report": helpers.is_deletion_report_requested(input.bundle),
	"route_key": null,
	"mutations": [],
} if {
	deny_hop_limit
}

# 4. Storm prevention / routing loop detected (duplicate bundle, TREB visited, APRS trap/loop).
decision := {
	"action": "DROP",
	"reason_code": constants.reason_hop_limit_exceeded,
	"reason": "Storm or routing loop prevented at ingress",
	"generate_status_report": false,
	"route_key": null,
	"mutations": [],
} if {
	deny_storm
}

# Compute next hop route key for APRS trajectory control when available.
aprs_next_strict_target(traj) := target if {
	idx := traj.active_hop_index
	hop := traj.path_elements[idx]
	helpers.is_strict_hop(hop)
	not helpers.is_strict_match(hop, input.node)
	target := hop.target_id
} else := target if {
	idx := traj.active_hop_index + 1
	idx < count(traj.path_elements)
	next_hop := traj.path_elements[idx]
	helpers.is_strict_hop(next_hop)
	target := next_hop.target_id
} else := input.bundle.primary.destination if {
	idx := traj.active_hop_index
	hop := traj.path_elements[idx]
	helpers.is_strict_match(hop, input.node)
	(idx + 1) >= count(traj.path_elements)
	not helpers.is_local_destination(input.bundle.primary.destination, input.node)
} else := null

aprs_can_service_alias if {
	helpers.has_aprs_trajectory(input.bundle)
	traj := helpers.get_trajectory_payload(input.bundle)
	hop := helpers.get_active_hop(traj)
	helpers.is_alias_hop(hop)
	hop.remaining_count > 0
	helpers.is_alias_supported(hop.scope_name, input.node)
}

aprs_can_consume_strict if {
	helpers.has_aprs_trajectory(input.bundle)
	traj := helpers.get_trajectory_payload(input.bundle)
	hop := helpers.get_active_hop(traj)
	helpers.is_strict_match(hop, input.node)
}

aprs_route_mutations := [
	{
		"block_type": constants.block_type_mesh_routing,
		"operation": "MUTATE_APRS_ALIAS",
		"field": "trajectory_control",
		"value": helpers.get_local_aprs_id(input.node),
	},
] if {
	aprs_can_service_alias
} else := [
	{
		"block_type": constants.block_type_mesh_routing,
		"operation": "MUTATE_APRS_STRICT",
		"field": "trajectory_control",
		"value": helpers.get_local_aprs_id(input.node),
	},
] if {
	aprs_can_consume_strict
} else := []

# 5. Valid APRS / trajectory bundle accepted with path mutations + TREB + Hop Count.
decision := {
	"action": "ACCEPT",
	"reason": "APRS trajectory bundle accepted",
	"generate_status_report": false,
	"route_key": aprs_next_strict_target(traj),
	"mutations": array.concat(hop_count_mutations, array.concat(aprs_route_mutations, treb_mutations)),
} if {
	transit_allowed
	helpers.has_aprs_trajectory(input.bundle)
	traj := helpers.get_trajectory_payload(input.bundle)
}

# 6. Standard / Spray-and-Wait / custom bundle transit acceptance.
decision := {
	"action": "ACCEPT",
	"reason": "Bundle accepted for forwarding / storage",
	"generate_status_report": false,
	"route_key": null,
	"mutations": array.concat(hop_count_mutations, treb_mutations),
} if {
	transit_allowed
	not helpers.has_aprs_trajectory(input.bundle)
}
