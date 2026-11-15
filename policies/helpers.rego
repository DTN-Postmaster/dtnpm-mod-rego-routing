package dtn.helpers

import rego.v1

import data.dtn.constants

# Extracts the first extension block matching block_type.
get_extension_block(blocks, block_type) := block if {
	some b in blocks
	b.block_type == block_type
	block := b
}

# Extracts any custom/unrecognized block payload by block_type.
get_custom_block(bundle, block_type) := b.payload if {
	b := get_extension_block(bundle.extension_blocks, block_type)
}

# Extracts the Hop Count Block (Type 10).
get_hop_count_block(bundle) := get_extension_block(bundle.extension_blocks, constants.block_type_hop_count)

# RFC 9171 §4.3.3: true when hop_count already equals or exceeds hop_limit.
is_hop_limit_reached(bundle) if {
	hcb := get_hop_count_block(bundle)
	hcb.hop_count >= hcb.hop_limit
}

# RFC 9171 §4.3.3: true when incrementing hop_count at ingress would reach or exceed hop_limit.
will_exceed_hop_limit(bundle) if {
	hcb := get_hop_count_block(bundle)
	(hcb.hop_count + 1) >= hcb.hop_limit
}

# Checks whether Bundle Deletion Status Report flag is requested.
is_deletion_report_requested(bundle) if {
	bundle.primary.processing_flags.delete_report_requested == true
}

# Checks bundle lifetime expiration using DTN clock or Bundle Age Block (Type 7).
is_lifetime_expired(bundle, current_dtn_time_ms) if {
	bundle.primary.creation_timestamp.time > 0
	elapsed := current_dtn_time_ms - bundle.primary.creation_timestamp.time
	elapsed >= bundle.primary.lifetime
}

is_lifetime_expired(bundle, _current_dtn_time_ms) if {
	bundle.primary.creation_timestamp.time == 0
	age_block := get_extension_block(bundle.extension_blocks, constants.block_type_bundle_age)
	age_block.age_ms >= bundle.primary.lifetime
}

# Returns true if an EID matches an exact pattern or wildcard pattern (e.g. dtn://spam/*, ipn:99.*).
eid_matches_pattern(eid, pattern) if {
	eid == pattern
}

eid_matches_pattern(eid, pattern) if {
	contains(pattern, "*")
	glob.match(pattern, [], eid)
}

# Checks whether source EID matches any configured node blacklist pattern.
is_source_blacklisted(source_eid, node) if {
	blacklist := object.get(node, "blacklist_sources", [])
	some pattern in blacklist
	eid_matches_pattern(source_eid, pattern)
}

# Returns true if two EIDs refer to the same DTN/IPN node (e.g. ipn:0.99.0 == ipn:0.99.1, dtn://statc/ == dtn://statc/files).
is_same_node(eid_a, eid_b) if {
	eid_a == eid_b
}

is_same_node(eid_a, eid_b) if {
	startswith(eid_a, "dtn://")
	startswith(eid_b, "dtn://")
	node_a := split(trim_prefix(eid_a, "dtn://"), "/")[0]
	node_b := split(trim_prefix(eid_b, "dtn://"), "/")[0]
	node_a != ""
	node_a == node_b
}

is_same_node(eid_a, eid_b) if {
	startswith(eid_a, "ipn:")
	startswith(eid_b, "ipn:")
	parts_a := split(trim_prefix(eid_a, "ipn:"), ".")
	parts_b := split(trim_prefix(eid_b, "ipn:"), ".")
	count(parts_a) == 3
	count(parts_b) == 3
	parts_a[0] == parts_b[0]
	parts_a[1] == parts_b[1]
}

is_same_node(eid_a, eid_b) if {
	startswith(eid_a, "ipn:")
	startswith(eid_b, "ipn:")
	parts_a := split(trim_prefix(eid_a, "ipn:"), ".")
	parts_b := split(trim_prefix(eid_b, "ipn:"), ".")
	count(parts_a) == 2
	count(parts_b) == 2
	parts_a[0] == parts_b[0]
}

# Returns all EIDs owned by the local BPA node.
is_local_destination(dest_eid, node) if {
	dest_eid == node.local_eid
}

is_local_destination(dest_eid, node) if {
	some local_id in object.get(node, "node_eids", [])
	dest_eid == local_id
}

# Canonical bundle deduplication key.
canonical_bundle_id(bundle) := sprintf("%s@%d#%d", [
	bundle.primary.source,
	bundle.primary.creation_timestamp.time,
	bundle.primary.creation_timestamp.sequence_number,
])

# Storm prevention: checks duplicate bundle against local seen_cache.
is_duplicate(bundle, node) if {
	seen := object.get(node, "seen_cache", [])
	cid := canonical_bundle_id(bundle)
	cid in seen
}

# Checks Previous Node Block (Type 6) for split-horizon loop avoidance.
is_from_peer(bundle, peer_eid) if {
	pib := get_extension_block(bundle.extension_blocks, constants.block_type_previous_node)
	pib.previous_node_eid == peer_eid
}

# Configurable TREB block type (default 201).
treb_block_type(node) := object.get(node, "treb_block_type", constants.default_block_type_treb)

get_treb_block(bundle, node) := block if {
	btype := treb_block_type(node)
	block := get_extension_block(bundle.extension_blocks, btype)
}

has_treb_block(bundle, node) if {
	_ := get_treb_block(bundle, node)
}

# Checks whether eid appears in recorded TREB hops (past path loop detection).
has_visited_node(bundle, node, eid) if {
	eid != ""
	treb := get_treb_block(bundle, node)
	hops := object.get(treb.payload, "hops", [])
	some hop in hops
	hop.node_eid == eid
}

# Mesh Routing Block (Type 200) helpers.
get_mesh_block(bundle) := get_extension_block(bundle.extension_blocks, constants.block_type_mesh_routing)

has_spray_block(bundle) if {
	mesh := get_mesh_block(bundle)
	_ := mesh.payload.replication_control
}

has_spray_block(bundle) if {
	_ := get_extension_block(bundle.extension_blocks, constants.block_type_spray_permit)
}

get_spray_quota(bundle) := quota if {
	mesh := get_mesh_block(bundle)
	quota := mesh.payload.replication_control.quota
}

get_spray_quota(bundle) := quota if {
	not mesh_has_replication(bundle)
	b194 := get_extension_block(bundle.extension_blocks, constants.block_type_spray_permit)
	quota := b194.payload.quota
}

mesh_has_replication(bundle) if {
	mesh := get_mesh_block(bundle)
	_ := mesh.payload.replication_control
}

get_spray_mode(bundle) := mode if {
	mesh := get_mesh_block(bundle)
	mode := object.get(mesh.payload.replication_control, "mode", constants.spray_mode_binary)
}

get_spray_mode(bundle) := constants.spray_mode_binary if {
	not mesh_has_replication(bundle)
	_ := get_extension_block(bundle.extension_blocks, constants.block_type_spray_permit)
}

calculate_binary_spray(quota) := {
	"send_quota": send_q,
	"keep_quota": keep_q,
	"new_local_phase": local_phase,
	"transmitted_phase": tx_phase,
} if {
	send_q := floor(quota / 2)
	keep_q := quota - send_q
	local_phase := phase_for_quota(keep_q)
	tx_phase := phase_for_quota(send_q)
}

phase_for_quota(q) := constants.spray_phase_wait if {
	q <= 1
}

phase_for_quota(q) := constants.spray_phase_disseminate if {
	q > 1
}

# APRS / Trajectory Control helpers (Block Type 200 future path).
has_aprs_trajectory(bundle) if {
	mesh := get_mesh_block(bundle)
	_ := mesh.payload.trajectory_control
}

get_trajectory_payload(bundle) := traj if {
	mesh := get_mesh_block(bundle)
	traj := mesh.payload.trajectory_control
}

get_active_hop(traj) := hop if {
	idx := traj.active_hop_index
	idx < count(traj.path_elements)
	hop := traj.path_elements[idx]
}

is_strict_hop(hop) if {
	kind := object.get(hop, "target_type", object.get(hop, "hop_kind", 0))
	kind == constants.hop_kind_strict
}

is_alias_hop(hop) if {
	kind := object.get(hop, "target_type", object.get(hop, "hop_kind", 0))
	kind == constants.hop_kind_alias
}

get_local_aprs_id(node) := cid if {
	cid := node.callsign
	cid != ""
}

get_local_aprs_id(node) := node.local_eid if {
	not has_nonempty_callsign(node)
}

has_nonempty_callsign(node) if {
	node.callsign != ""
}

is_strict_match(hop, node) if {
	is_strict_hop(hop)
	target := object.get(hop, "target_id", "")
	target != ""
	target == node.local_eid
}

is_strict_match(hop, node) if {
	is_strict_hop(hop)
	target := object.get(hop, "target_id", "")
	target != ""
	has_nonempty_callsign(node)
	target == node.callsign
}

is_alias_supported(alias_name, node) if {
	alias_name in object.get(node, "supported_aliases", [])
}

is_trapped_alias(alias_name, node) if {
	alias_name in object.get(node, "trapped_aliases", [])
}

# Dire Wolf Rule 6.1(b): packet originated from our own station.
is_own_packet(bundle, node) if {
	bundle.primary.source == node.local_eid
}

is_own_packet(bundle, node) if {
	has_nonempty_callsign(node)
	bundle.primary.source == node.callsign
}

# Dire Wolf Rule 6.3(c): alias hop already serviced by this digipeater.
is_already_serviced_by_us(traj, node) if {
	my_id := get_local_aprs_id(node)
	some elem in traj.path_elements
	object.get(elem, "serviced_by", "") == my_id
}

# Detects storm/loop conditions (duplicate bundle, TREB visited node, or APRS digipeat loop/trap).
is_aprs_loop_or_trap(bundle, node) if {
	has_aprs_trajectory(bundle)
	traj := get_trajectory_payload(bundle)
	hop := get_active_hop(traj)
	is_alias_hop(hop)
	is_trapped_alias(hop.scope_name, node)
}

is_externally_received(bundle, _node) if {
	get_extension_block(bundle.extension_blocks, constants.block_type_previous_node)
}

is_externally_received(bundle, node) if {
	treb := get_treb_block(bundle, node)
	count(object.get(treb.payload, "hops", [])) > 0
}

is_aprs_loop_or_trap(bundle, node) if {
	has_aprs_trajectory(bundle)
	is_own_packet(bundle, node)
	is_externally_received(bundle, node)
}

is_aprs_loop_or_trap(bundle, node) if {
	has_aprs_trajectory(bundle)
	traj := get_trajectory_payload(bundle)
	is_already_serviced_by_us(traj, node)
}

is_storm_or_loop(bundle, node) if {
	is_duplicate(bundle, node)
}

is_storm_or_loop(bundle, node) if {
	has_visited_node(bundle, node, node.local_eid)
}

is_storm_or_loop(bundle, node) if {
	is_aprs_loop_or_trap(bundle, node)
}

# Checks whether a neighbor peer is not blacklisted on the local node.
peer_allowed(peer, node) if {
	not is_source_blacklisted(peer.peer_eid, node)
}
