package dtn.constants

import rego.v1

# BPv7 Standard Extension Block Types (RFC 9171)
block_type_previous_node := 6
block_type_bundle_age := 7
block_type_hop_count := 10

# Experimental / Extension Block Types (IANA 192-255)
block_type_spray_permit := 194
block_type_mesh_routing := 200
default_block_type_treb := 201

# BPv7 Administrative Record Status Report Reason Codes (RFC 9171 §6.1.1)
reason_no_additional_info := 0
reason_lifetime_expired := 1
reason_forwarded_over_unidirectional_link := 2
reason_transmission_canceled := 3
reason_depleted_storage := 4
reason_destination_eid_unintelligible := 5
reason_no_known_route := 6
reason_no_timely_contact := 7
reason_block_unintelligible := 8
reason_hop_limit_exceeded := 9

# Spray-and-Wait Replication Modes & Phases (Block 200 replication_control)
spray_mode_source := 1
spray_mode_binary := 2

spray_phase_disseminate := 1
spray_phase_wait := 2

# APRS / Source Trajectory Hop Kinds (Block 200 trajectory_control)
hop_kind_strict := 1
hop_kind_alias := 2
