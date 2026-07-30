package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/ws"
)

const (
	unlockQualityBodyLimit  = 64 << 10
	unlockQualityMaxSamples = 3
)

var unlockQualityRunning sync.Map

type unlockEndpointSpec struct {
	key       string
	target    string
	quality   bool
	traceInfo bool
}

type unlockHTTPSample struct {
	dns             time.Duration
	connect         time.Duration
	tls             time.Duration
	ttfb            time.Duration
	total           time.Duration
	statusCode      int
	statusOK        bool
	retransmissions int
	addressHash     string
	addressFamily   string
	body            string
}

type unlockHTTPTrace struct {
	mu            sync.Mutex
	dns           time.Duration
	connect       time.Duration
	tls           time.Duration
	requestStart  time.Time
	firstByteAt   time.Time
	connectStart  time.Time
	tlsStart      time.Time
	currentConn   net.Conn
	addressHash   string
	addressFamily string
}

func NewUnlockQualityTask(conn *ws.SafeConn, params v2.UnlockQualityParams) {
	if err := validateUnlockQualityParams(params); err != nil {
		return
	}
	taskKey := fmt.Sprintf("%d:%s", params.TaskID, params.RouteMode)
	if _, loaded := unlockQualityRunning.LoadOrStore(taskKey, params.RunID); loaded {
		uploadUnlockQualityResult(conn, v2.UnlockQualityResultParams{
			TaskID:          params.TaskID,
			RunID:           params.RunID,
			Service:         params.Service,
			CatalogRevision: params.CatalogRevision,
			RouteMode:       params.RouteMode,
			ProbeKind:       params.ProbeKind,
			Verdict:         "unavailable",
			ErrorCode:       "task_already_running",
			FinishedAt:      time.Now().UTC(),
		})
		return
	}
	defer unlockQualityRunning.Delete(taskKey)

	results, verdict, errorCode := performUnlockQualityTask(params)
	uploadUnlockQualityResult(conn, v2.UnlockQualityResultParams{
		TaskID:          params.TaskID,
		RunID:           params.RunID,
		Service:         params.Service,
		CatalogRevision: params.CatalogRevision,
		RouteMode:       params.RouteMode,
		ProbeKind:       params.ProbeKind,
		Verdict:         verdict,
		Results:         results,
		ErrorCode:       errorCode,
		FinishedAt:      time.Now().UTC(),
	})
}

func validateUnlockQualityParams(params v2.UnlockQualityParams) error {
	if params.TaskID == 0 || !validTCPQualityID(params.RunID, 64) ||
		!validTCPQualityID(params.CatalogRevision, 64) {
		return errors.New("invalid unlock quality task identity")
	}
	if params.Service != "chatgpt" {
		return errors.New("unsupported unlock service")
	}
	if params.RouteMode != "system" && params.RouteMode != "control" && params.RouteMode != "fixed" {
		return errors.New("invalid unlock route mode")
	}
	if params.ProbeKind != "minute" && params.ProbeKind != "verify" {
		return errors.New("invalid unlock probe kind")
	}
	if params.SampleCount < 1 || params.SampleCount > unlockQualityMaxSamples ||
		params.TimeoutMS < 1000 || params.TimeoutMS > 30000 {
		return errors.New("invalid unlock quality probe limits")
	}
	switch params.RouteMode {
	case "system":
		if strings.TrimSpace(params.DNSServer) != "" || strings.TrimSpace(params.FixedAddress) != "" {
			return errors.New("system route must not override DNS or address")
		}
	case "control":
		if normalizeTaskDNSServer(params.DNSServer) == "" || strings.TrimSpace(params.FixedAddress) != "" {
			return errors.New("control route requires a valid DNS server")
		}
	case "fixed":
		if net.ParseIP(strings.TrimSpace(params.FixedAddress)) == nil || strings.TrimSpace(params.DNSServer) != "" {
			return errors.New("fixed route requires an IP address")
		}
	}
	return nil
}

func performUnlockQualityTask(params v2.UnlockQualityParams) ([]v2.UnlockQualityEndpointResult, string, string) {
	specs := []unlockEndpointSpec{{
		key: "web", target: "https://chatgpt.com/", quality: true,
	}}
	if params.ProbeKind == "verify" {
		specs = append(specs,
			unlockEndpointSpec{key: "auth", target: "https://auth.openai.com/"},
			unlockEndpointSpec{key: "api", target: "https://api.openai.com/v1/models"},
			unlockEndpointSpec{key: "static", target: "https://cdn.oaistatic.com/"},
			unlockEndpointSpec{key: "trace", target: "https://chatgpt.com/cdn-cgi/trace", traceInfo: true},
		)
	}

	results := make([]v2.UnlockQualityEndpointResult, 0, len(specs))
	for _, spec := range specs {
		count := 1
		if spec.quality {
			count = params.SampleCount
		}
		results = append(results, runUnlockEndpoint(params, spec, count))
	}
	verdict := classifyChatGPTUnlock(results, params.ProbeKind)
	errorCode := ""
	if verdict == "unavailable" {
		errorCode = "service_unavailable"
	}
	return results, verdict, errorCode
}

func runUnlockEndpoint(params v2.UnlockQualityParams, spec unlockEndpointSpec, count int) v2.UnlockQualityEndpointResult {
	result := v2.UnlockQualityEndpointResult{
		EndpointKey: spec.key,
		SamplesSent: count,
		Verdict:     "unavailable",
	}
	var dnsTotal, connectTotal, tlsTotal time.Duration
	var ttfbValues, totalValues []float64
	var statusOK, retransmissions int
	var lastError error
	var lastBody string

	for i := 0; i < count; i++ {
		sample, err := performUnlockHTTPSample(params, spec.target)
		if err != nil {
			lastError = err
			continue
		}
		result.SamplesReceived++
		dnsTotal += sample.dns
		connectTotal += sample.connect
		tlsTotal += sample.tls
		ttfbValues = append(ttfbValues, durationMS(sample.ttfb))
		totalValues = append(totalValues, durationMS(sample.total))
		result.HTTPStatusCode = sample.statusCode
		result.ResolvedAddressHash = sample.addressHash
		result.ResolvedAddressFamily = sample.addressFamily
		retransmissions += sample.retransmissions
		if sample.statusOK {
			statusOK++
		}
		lastBody = sample.body
	}

	result.FailureRatio = float64(count-result.SamplesReceived) / float64(count)
	result.TCPRetransmissions = retransmissions
	if result.SamplesReceived == 0 {
		result.ErrorCode = probeErrorCode(lastError)
		return result
	}
	result.DNSMS = durationAverageMS(dnsTotal, result.SamplesReceived)
	result.ConnectMS = durationAverageMS(connectTotal, result.SamplesReceived)
	result.TLSMS = durationAverageMS(tlsTotal, result.SamplesReceived)
	result.TTFBP50MS = unlockQuantile(ttfbValues, 0.50)
	result.TTFBP95MS = unlockQuantile(ttfbValues, 0.95)
	result.TotalP50MS = unlockQuantile(totalValues, 0.50)
	result.TotalP95MS = unlockQuantile(totalValues, 0.95)
	result.JitterMS = unlockStdDev(ttfbValues)
	result.HTTPStatusOKRatio = float64(statusOK) / float64(result.SamplesReceived)
	result.Verdict = classifyChatGPTEndpoint(spec.key, result.HTTPStatusCode, lastBody)
	if spec.traceInfo {
		trace := parseCloudflareTrace(lastBody)
		result.ExitCountry = trace["loc"]
		result.EdgeColo = trace["colo"]
	}
	if result.SamplesReceived < count {
		result.ErrorCode = "partial_failure"
	}
	return result
}

func performUnlockHTTPSample(params v2.UnlockQualityParams, target string) (unlockHTTPSample, error) {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || !allowedUnlockHost(parsed.Hostname()) {
		return unlockHTTPSample{}, errors.New("invalid unlock endpoint")
	}
	traceState := &unlockHTTPTrace{}
	timeout := time.Duration(params.TimeoutMS) * time.Millisecond
	transport := &http.Transport{
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			var addresses []net.IPAddr
			dnsStart := time.Now()
			if params.RouteMode == "fixed" {
				addresses = []net.IPAddr{{IP: net.ParseIP(strings.TrimSpace(params.FixedAddress))}}
			} else {
				resolver := taskResolver("")
				if params.RouteMode == "control" {
					resolver = taskResolver(params.DNSServer)
				}
				var lookupErr error
				addresses, _, lookupErr = lookupProbeAddresses(ctx, resolver, host, "")
				if lookupErr != nil {
					return nil, lookupErr
				}
			}
			traceState.mu.Lock()
			traceState.dns += time.Since(dnsStart)
			traceState.addressHash, traceState.addressFamily = addressFingerprint(addresses)
			traceState.mu.Unlock()

			var lastErr error
			for _, address := range addresses {
				dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(address.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			if request.URL.Scheme != "https" || !allowedUnlockHost(request.URL.Hostname()) {
				return errors.New("unlock endpoint redirected outside the allowlist")
			}
			return nil
		},
	}
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return unlockHTTPSample{}, err
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125 Safari/537.36 Komari-Cazi/1.0")
	request.Header.Set("Accept", "text/html,application/json;q=0.9,*/*;q=0.8")

	clientTrace := &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			traceState.mu.Lock()
			traceState.connectStart = time.Now()
			traceState.mu.Unlock()
		},
		ConnectDone: func(_, _ string, _ error) {
			traceState.mu.Lock()
			if !traceState.connectStart.IsZero() {
				traceState.connect += time.Since(traceState.connectStart)
				traceState.connectStart = time.Time{}
			}
			traceState.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			traceState.mu.Lock()
			traceState.tlsStart = time.Now()
			traceState.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			traceState.mu.Lock()
			if !traceState.tlsStart.IsZero() {
				traceState.tls += time.Since(traceState.tlsStart)
				traceState.tlsStart = time.Time{}
			}
			traceState.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			traceState.mu.Lock()
			traceState.currentConn = info.Conn
			traceState.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			traceState.mu.Lock()
			traceState.firstByteAt = time.Now()
			traceState.mu.Unlock()
		},
	}

	start := time.Now()
	traceState.requestStart = start
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), clientTrace))
	response, err := client.Do(request)
	total := time.Since(start)
	if err != nil {
		return unlockHTTPSample{}, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, unlockQualityBodyLimit))
	_ = response.Body.Close()
	if readErr != nil {
		return unlockHTTPSample{}, readErr
	}

	traceState.mu.Lock()
	defer traceState.mu.Unlock()
	ttfb := time.Duration(0)
	if !traceState.firstByteAt.IsZero() {
		ttfb = traceState.firstByteAt.Sub(traceState.requestStart)
	}
	return unlockHTTPSample{
		dns:             traceState.dns,
		connect:         traceState.connect,
		tls:             traceState.tls,
		ttfb:            ttfb,
		total:           total,
		statusCode:      response.StatusCode,
		statusOK:        response.StatusCode < 500,
		retransmissions: tcpRetransmissions(traceState.currentConn),
		addressHash:     traceState.addressHash,
		addressFamily:   traceState.addressFamily,
		body:            string(body),
	}, nil
}

func allowedUnlockHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	for _, suffix := range []string{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com"} {
		if host == suffix || strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

func classifyChatGPTEndpoint(key string, status int, body string) string {
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"unsupported_country", "country is not supported", "not available in your country",
		"service is not available in your region",
	} {
		if strings.Contains(lower, marker) {
			return "region_limited"
		}
	}
	if status == 0 || status >= 500 {
		return "unavailable"
	}
	switch key {
	case "api":
		if status == http.StatusOK || status == http.StatusUnauthorized ||
			status == http.StatusForbidden || status == http.StatusTooManyRequests {
			return "available"
		}
	case "trace":
		if status == http.StatusOK && strings.Contains(lower, "colo=") {
			return "available"
		}
	case "web", "auth", "static":
		// ChatGPT and its CDN commonly return 403/404 to non-browser probes.
		// A completed non-5xx HTTPS response still proves regional reachability.
		if status >= 200 && status < 500 {
			return "available"
		}
	}
	return "partial"
}

func classifyChatGPTUnlock(results []v2.UnlockQualityEndpointResult, probeKind string) string {
	if len(results) == 0 {
		return "unavailable"
	}
	available, partial := 0, 0
	for _, result := range results {
		if result.Verdict == "region_limited" {
			return "region_limited"
		}
		switch result.Verdict {
		case "available":
			available++
		case "partial":
			partial++
		}
	}
	if probeKind == "minute" {
		if available == 1 {
			return "available"
		}
		if partial == 1 {
			return "partial"
		}
		return "unavailable"
	}
	if available >= 4 && available+partial == len(results) {
		return "available"
	}
	if available > 0 || partial > 0 {
		return "partial"
	}
	return "unavailable"
}

func parseCloudflareTrace(body string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(body, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.ToUpper(strings.TrimSpace(value))
		if (key == "loc" && len(value) == 2) || (key == "colo" && len(value) == 3) {
			result[key] = value
		}
	}
	return result
}

func unlockQuantile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	position := float64(len(sorted)-1) * percentile
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	fraction := position - float64(lower)
	return sorted[lower]*(1-fraction) + sorted[upper]*fraction
}

func unlockStdDev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	var total float64
	for _, value := range values {
		total += value
	}
	average := total / float64(len(values))
	var variance float64
	for _, value := range values {
		delta := value - average
		variance += delta * delta
	}
	return math.Sqrt(variance / float64(len(values)))
}

func durationMS(value time.Duration) float64 {
	return float64(value.Microseconds()) / 1000
}

func uploadUnlockQualityResult(conn *ws.SafeConn, params v2.UnlockQualityResultParams) {
	payload := v2.BuildUnlockQualityResultPayload(params)
	if conn == nil {
		if err := postV2RPC(payload); err != nil {
			fmt.Printf("Failed to upload unlock quality result over POST: %v\n", err)
		}
		return
	}
	if err := conn.WriteJSON(payload); err != nil {
		fmt.Printf("Failed to upload unlock quality result over WebSocket: %v\n", err)
	}
}
