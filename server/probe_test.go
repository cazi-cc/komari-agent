package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

func TestHTTPProbeKeepsReachabilitySeparateFromStatusHealth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	value, details, err := performProbe("http", server.URL, v2.ProbeOptions{SampleCount: 3})
	if err != nil {
		t.Fatalf("performProbe returned an error for an HTTP response: %v", err)
	}
	if value < 0 {
		t.Fatalf("value = %d, want a reachable latency", value)
	}
	if details == nil || !details.Reachable {
		t.Fatalf("details = %#v, want reachable response", details)
	}
	if details.SamplesReceived != 3 || details.LossRatio != 0 {
		t.Fatalf("samples/loss = %d/%v, want 3/0", details.SamplesReceived, details.LossRatio)
	}
	if details.HTTPStatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", details.HTTPStatusCode, http.StatusForbidden)
	}
	if details.HTTPStatusOKRatio != 0 {
		t.Fatalf("status OK ratio = %v, want 0", details.HTTPStatusOKRatio)
	}
}

func TestHTTPProbeAllowsConfiguredStatusCodes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	_, details, err := performProbe("http", server.URL, v2.ProbeOptions{
		SampleCount:      2,
		ValidStatusCodes: []int{http.StatusForbidden},
	})
	if err != nil {
		t.Fatalf("performProbe: %v", err)
	}
	if details.HTTPStatusOKRatio != 1 {
		t.Fatalf("status OK ratio = %v, want 1", details.HTTPStatusOKRatio)
	}
}

func TestNormalizeProbeOptionsBoundsResourceUse(t *testing.T) {
	options := normalizeProbeOptions(v2.ProbeOptions{
		PacketSize:  9000,
		SampleCount: 100,
		TimeoutMS:   60000,
	}, "icmp")
	if options.packetSize != maxICMPPacketSize {
		t.Fatalf("packet size = %d, want %d", options.packetSize, maxICMPPacketSize)
	}
	if options.sampleCount != maxProbeSamples {
		t.Fatalf("sample count = %d, want %d", options.sampleCount, maxProbeSamples)
	}
	if options.timeout.Milliseconds() != maxProbeTimeoutMS {
		t.Fatalf("timeout = %dms, want %dms", options.timeout.Milliseconds(), maxProbeTimeoutMS)
	}
}
