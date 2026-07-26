package server

import (
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
