package server

import (
	"math"
	"slices"
	"testing"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

func TestParseNpingBatchOutput(t *testing.T) {
	output := `SENT (0.0350s) TCP 192.0.2.10:53 > 198.51.100.20:443 S ttl=64 id=1 iplen=40  seq=1 win=1480
RCVD (0.0460s) TCP 198.51.100.20:443 > 192.0.2.10:53 SA ttl=56 id=2 iplen=44  seq=1 win=64240 <mss 1460> rtt=11.000ms
SENT (0.2350s) TCP 192.0.2.10:53 > 198.51.100.20:443 S ttl=64 id=3 iplen=40  seq=2 win=1480
RCVD (0.2475s) TCP 198.51.100.20:443 > 192.0.2.10:53 SA ttl=56 id=4 iplen=44  seq=2 win=64240 <mss 1460> rtt=12.500ms
Max rtt: 12.500ms | Min rtt: 11.000ms | Avg rtt: 11.750ms
Raw packets sent: 3 (120B) | Rcvd: 2 (88B) | Lost: 1 (33.33%)`
	latencies, received := parseNpingBatchOutput(output)
	if received != 2 {
		t.Fatalf("received = %d, want 2", received)
	}
	if len(latencies) != 2 || latencies[0] != 11 || latencies[1] != 12.5 {
		t.Fatalf("latencies = %#v, want [11 12.5]", latencies)
	}
}

func TestParseNpingBatchOutputFromEventTimestamps(t *testing.T) {
	output := `SENT (0.0068s) TCP 192.0.2.10:62952 > 198.51.100.20:80 S ttl=64 id=1 iplen=40 seq=1 win=1480
SENT (0.2071s) TCP 192.0.2.10:62952 > 198.51.100.20:80 S ttl=64 id=1 iplen=40 seq=1 win=1480
RCVD (0.3700s) TCP 198.51.100.20:80 > 192.0.2.10:62952 SA ttl=46 id=0 iplen=44 seq=2 win=64240
SENT (0.4071s) TCP 192.0.2.10:62952 > 198.51.100.20:80 S ttl=64 id=1 iplen=40 seq=1 win=1480
RCVD (0.7711s) TCP 198.51.100.20:80 > 192.0.2.10:62952 SA ttl=46 id=0 iplen=44 seq=3 win=64240
Max rtt: 364.017ms | Min rtt: 162.909ms | Avg rtt: 263.463ms
Raw packets sent: 3 (120B) | Rcvd: 2 (92B) | Lost: 1 (33.33%)`
	latencies, received := parseNpingBatchOutput(output)
	if received != 2 {
		t.Fatalf("received = %d, want 2", received)
	}
	if len(latencies) != 2 || math.Abs(latencies[0]-162.9) > 0.001 || math.Abs(latencies[1]-364) > 0.001 {
		t.Fatalf("latencies = %#v, want approximately [162.9 364.0]", latencies)
	}
}

func TestParseNpingBatchOutputIgnoresICMPResponses(t *testing.T) {
	output := `SENT (0.1000s) TCP 192.0.2.10:50000 > 198.51.100.20:80 S ttl=64
RCVD (0.1100s) ICMP 198.51.100.1 > 192.0.2.10 Destination port unreachable
Raw packets sent: 1 (40B) | Rcvd: 1 (56B) | Lost: 0 (0.00%)`
	latencies, received := parseNpingBatchOutput(output)
	if received != 0 || len(latencies) != 0 {
		t.Fatalf("ICMP response counted as TCP success: received=%d latencies=%#v", received, latencies)
	}
}

func TestValidateTCPQualityParamsRejectsHostnames(t *testing.T) {
	params := v2.TCPQualityParams{
		TaskID:          1,
		RunID:           "run_1",
		CatalogRevision: "revision_1",
		Targets: []v2.TCPQualityTarget{{
			Key: "hk-ct-v4", Address: "example.com", Port: 443, IPVersion: 4,
		}},
		StandardPackets: 30,
		LargePackets:    30,
		DelayMS:         200,
		TimeoutMS:       3000,
	}
	if err := validateTCPQualityParams(params); err == nil {
		t.Fatal("expected hostname target to be rejected")
	}
}

func TestFloatQuantile(t *testing.T) {
	values := []float64{10, 20, 30, 40}
	if got := floatQuantile(values, 0.5); got != 25 {
		t.Fatalf("P50 = %v, want 25", got)
	}
	if got := floatQuantile(values, 0.95); got != 38.5 {
		t.Fatalf("P95 = %v, want 38.5", got)
	}
}

func TestBuildNpingBatchArgsUsesExplicitIPv6Route(t *testing.T) {
	target := v2.TCPQualityTarget{
		Address: "2001:db8::20", Port: 80, IPVersion: 6,
	}
	route := &npingIPv6Route{
		Interface:      "eth0",
		SourceIP:       "2001:db8::10",
		SourceMAC:      "00:11:22:33:44:55",
		DestinationMAC: "66:77:88:99:aa:bb",
	}
	args := buildNpingBatchArgs(target, 0, 30, 200, route)
	for _, expected := range []string{
		"-6", "-e", "eth0", "-S", "2001:db8::10",
		"--source-mac", "00:11:22:33:44:55",
		"--dest-mac", "66:77:88:99:aa:bb",
	} {
		if !slices.Contains(args, expected) {
			t.Fatalf("args = %#v, missing %q", args, expected)
		}
	}
	if slices.Contains(args, "--privileged") {
		t.Fatalf("explicit L2 args must not include --privileged: %#v", args)
	}
}

func TestParseNpingIPv6Route(t *testing.T) {
	interfaceName, sourceIP, nextHop := parseNpingIPv6Route(
		"240e:d6::92 from :: via 2001:db8::1 dev eth0 src 2001:db8:1::10 metric 1024 pref medium",
	)
	if interfaceName != "eth0" || sourceIP != "2001:db8:1::10" || nextHop != "2001:db8::1" {
		t.Fatalf("route = %q %q %q", interfaceName, sourceIP, nextHop)
	}
}

func TestParseNpingIPv6Neighbor(t *testing.T) {
	output := "2001:db8::1 lladdr 66:77:88:99:AA:BB router REACHABLE"
	if got := parseNpingIPv6Neighbor(output); got != "66:77:88:99:aa:bb" {
		t.Fatalf("neighbor MAC = %q", got)
	}
}
