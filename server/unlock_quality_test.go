package server

import (
	"testing"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
)

func TestParseCloudflareTraceDoesNotExposeIP(t *testing.T) {
	got := parseCloudflareTrace("fl=1\nip=2001:db8::1\nloc=jp\ncolo=sin\nwarp=off\n")
	if got["loc"] != "JP" || got["colo"] != "SIN" {
		t.Fatalf("unexpected trace fields: %#v", got)
	}
	if _, ok := got["ip"]; ok {
		t.Fatal("trace parser must not retain the visitor or exit IP")
	}
}

func TestClassifyChatGPTUnlock(t *testing.T) {
	results := []v2.UnlockQualityEndpointResult{
		{EndpointKey: "web", Verdict: "available"},
		{EndpointKey: "auth", Verdict: "available"},
		{EndpointKey: "api", Verdict: "available"},
		{EndpointKey: "static", Verdict: "partial"},
		{EndpointKey: "trace", Verdict: "available"},
	}
	if got := classifyChatGPTUnlock(results, "verify"); got != "available" {
		t.Fatalf("verdict = %q, want available", got)
	}
	results[2].Verdict = "region_limited"
	if got := classifyChatGPTUnlock(results, "verify"); got != "region_limited" {
		t.Fatalf("verdict = %q, want region_limited", got)
	}
}

func TestValidateUnlockQualityParams(t *testing.T) {
	base := v2.UnlockQualityParams{
		TaskID: 1, RunID: "run_1", Service: "chatgpt", CatalogRevision: "chatgpt_v1",
		RouteMode: "system", ProbeKind: "minute", SampleCount: 1, TimeoutMS: 10000,
	}
	if err := validateUnlockQualityParams(base); err != nil {
		t.Fatalf("valid params rejected: %v", err)
	}
	base.RouteMode = "control"
	base.DNSServer = "1.1.1.1"
	if err := validateUnlockQualityParams(base); err != nil {
		t.Fatalf("valid control params rejected: %v", err)
	}
	base.RouteMode = "fixed"
	base.DNSServer = ""
	base.FixedAddress = "167.148.203.139"
	if err := validateUnlockQualityParams(base); err != nil {
		t.Fatalf("valid fixed params rejected: %v", err)
	}
}
