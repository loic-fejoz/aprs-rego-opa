# A digipeater policy example as decribed in
# https://raw.githubusercontent.com/wb2osz/aprsspec/main/APRS-Digipeater-Algorithm.pdf
#
# For usage example, especially the expected input and data, please look at [digipeat_test.rego](./digipeat_test.rego)
package aprs.digipeat

import rego.v1

# Create what matters to identify a packet.
# It is use in particular to avoid duplication on air.
packet_id(pckt) := value if {
	value := [pckt.source, pckt.destination, pckt.payload]
}

default next_wide_value := []

# Evaluate next XXXn-M paradigm value (if valid)
next_wide_value := [p, n, m] if {
	some p in data.cfg.allowed_prefix
	startswith(input.packet.via_path.unused[0], p)
	values := split(substring(input.packet.via_path.unused[0], count(p), -1), "-")
	n := to_number(values[0])
	m := to_number(values[1]) - 1
}

is_wide_valid if {
	count(next_wide_value) > 0
	next_wide_value[2] >= 0
	next_wide_value[1] >= next_wide_value[2]
}

new_unused contains p if {
	is_wide_valid
	next_wide_value[2] > 0
	p := concat("", [
		next_wide_value[0],
		json.marshal(next_wide_value[1]),
		"-",
		json.marshal(next_wide_value[2]),
	])
}

default allow := false

allow if {
	input.packet.via_path.unused[0] == data.cfg.digicall
}

allow if {
	input.packet.via_path.unused[0] in data.cfg.aliases
}

allow if {
	is_wide_valid
}

deny contains "Packet already digipeated" if {
	data.digicall in input.packet.via_path.used
}

deny contains "Duplicate suppressed" if {
	input.history[packet_id(input.packet)] >= time.now_ns() - data.cfg.history_length
}

deny contains "Not digipeating myself" if {
	input.packet.source == data.cfg.digicall
}

transmit.source := input.packet.source

transmit.destination := input.packet.destination

transmit.payload := input.packet.payload

transmit.via_path.used := array.concat(input.packet.via_path.used, [data.cfg.digicall])

transmit.via_path.unused := array.concat(
	json.unmarshal(json.marshal(new_unused)),
	array.slice(input.packet.via_path.unused, 1, 20),
)
