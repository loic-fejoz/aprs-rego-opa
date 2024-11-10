package aprs.digipeat_test

import rego.v1

import data.aprs.digipeat

# An example of configuration of the digipeater
# NB: up to 4 aliases in older TNC
config1 := {
	# digipeater's callsign
	"digicall": "N2GH",
	# aliases of the digipeater.
	"aliases": ["EOC"],
	# Time limit for duplication.
	# Usually 30s
	"history_length": time.parse_duration_ns("30s"),
	# Accepted prefix for XXXn-N n-N paradigm
	"allowed_prefix": ["WIDE"],
}

# An input example for the policy.
# It contains mainly the cache of latest packets retransmitted,
# and the newer packet to handle.
input_example1 := {
	"history": {},
	"packet": {
		"source": "WB2OSZ",
		"destination": "APDW18",
		"via_path": {
			"used": [],
			"unused": [
				"N2GH",
				"W2UB",
			],
		},
		"payload": "something",
	},
}

input_example1_id := digipeat.packet_id(input_example1.packet)

input_example1_with_history := json.patch(
	input_example1,
	[{"op": "replace", "path": "/history", "value": {input_example1_id: time.now_ns()}}],
)

test_allow_if_next_unused_is_digipeater if {
	count(digipeat.deny) == 0 with input as input_example1
		with data.cfg as config1
}

test_deny_if_not_next_unused if {
	not digipeat.allow with input as input_example1
		with data.cfg as config1
		with data.cfg.digicall as "F4JXQ"
}

test_repeated_when_alias if {
	digipeat.transmit.via_path.used == ["N2GH"] with input as input_example1
		with data.cfg as config1
		with data.cfg.packet.via_path.unused as ["EOC"]
}

test_duplicate_suppression if {
	"Duplicate suppressed" in digipeat.deny with input as input_example1_with_history
		with data.cfg as config1
}

test_not_digipeating_my_message if {
	"Not digipeating myself" in digipeat.deny with input as input_example1
		with input.packet.source as config1.digicall
		with data.cfg as config1
}

test_wide11 if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, []] with input as input_example1
		with input.packet.via_path.unused as ["WIDE1-1"]
		with data.cfg as config1
}

test_wide22 if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, ["WIDE1-2"]] with input as input_example1
		with input.packet.via_path.unused as ["WIDE2-2"]
		with data.cfg as config1
}

test_wide22_unused_path if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, ["WIDE1-2"]]
		with input.packet.via_path.unused as ["WIDE2-2"]
		with data.cfg as config1
		with data.cfg.allowed_prefix as ["WIDE", "MA"]
}

test_wide12 if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, []] with input as input_example1
		with input.packet.via_path.unused as ["WIDE1-2"]
		with data.cfg as config1
}

test_wide71_error if {
	not digipeat.allow with input as input_example1
		with input.packet.via_path.unused as ["WIDE7-1"]
		with data.cfg as config1
}

test_wide01_error if {
	not digipeat.allow with input as input_example1
		with input.packet.via_path.unused as ["WIDE0-1"]
		with data.cfg as config1
}

test_ma11_accepted if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, []] with input as input_example1
		with input.packet.via_path.unused as ["MA1-1"]
		with data.cfg as config1
		with data.cfg.allowed_prefix as ["WIDE", "MA"]
}

test_ma22_accepted if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, ["MA1-2"]] with input as input_example1
		with input.packet.via_path.unused as ["MA2-2"]
		with data.cfg as config1
		with data.cfg.allowed_prefix as ["WIDE", "MA"]
}

test_wide11_wide_accepted if {
	[digipeat.allow, digipeat.transmit.via_path.unused] == [true, []] with input as input_example1
		with input.packet.via_path.unused as ["WIDE1-1"]
		with data.cfg as config1
		with data.cfg.allowed_prefix as ["WIDE", "MA"]
}
