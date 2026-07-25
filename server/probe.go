package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
	ping "github.com/prometheus-community/pro-bing"
)

const (
	defaultProbeTimeoutMS = 3000
	maxProbeTimeoutMS     = 10000
	maxProbeSamples       = 10
	defaultICMPPacketSize = 56
	maxICMPPacketSize     = 1400
)

type normalizedProbeOptions struct {
	packetSize       int
	sampleCount      int
	timeout          time.Duration
	dnsServer        string
	preferredIP      string
	validStatusCodes map[int]struct{}
}

func normalizeProbeOptions(raw v2.ProbeOptions, pingType string) normalizedProbeOptions {
	sampleCount := raw.SampleCount
	if sampleCount <= 0 {
		sampleCount = 1
	}
	if sampleCount > maxProbeSamples {
		sampleCount = maxProbeSamples
	}

	timeoutMS := raw.TimeoutMS
	if timeoutMS <= 0 {
		timeoutMS = defaultProbeTimeoutMS
	}
	if timeoutMS > maxProbeTimeoutMS {
		timeoutMS = maxProbeTimeoutMS
	}

	packetSize := raw.PacketSize
	if pingType == "icmp" && packetSize == 0 {
		packetSize = defaultICMPPacketSize
	}
	if packetSize < 0 {
		packetSize = 0
	}
	if packetSize > maxICMPPacketSize {
		packetSize = maxICMPPacketSize
	}

	preferredIP := strings.TrimSpace(raw.PreferredIP)
	if preferredIP != "4" && preferredIP != "6" {
		preferredIP = ""
	}

	validStatusCodes := make(map[int]struct{}, len(raw.ValidStatusCodes))
	for _, status := range raw.ValidStatusCodes {
		if status >= 100 && status <= 599 {
			validStatusCodes[status] = struct{}{}
		}
	}

	return normalizedProbeOptions{
		packetSize:       packetSize,
		sampleCount:      sampleCount,
		timeout:          time.Duration(timeoutMS) * time.Millisecond,
		dnsServer:        normalizeTaskDNSServer(raw.DNSServer),
		preferredIP:      preferredIP,
		validStatusCodes: validStatusCodes,
	}
}

func normalizeTaskDNSServer(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if ip := net.ParseIP(server); ip != nil && ip.To4() == nil {
		return net.JoinHostPort(server, "53")
	}
	return net.JoinHostPort(server, "53")
}

func taskResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: 3 * time.Second}
			return dialer.DialContext(ctx, network, server)
		},
	}
}

func lookupProbeAddresses(ctx context.Context, resolver *net.Resolver, host, preferredIP string) ([]net.IPAddr, time.Duration, error) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return []net.IPAddr{{IP: ip}}, 0, nil
	}
	start := time.Now()
	addresses, err := resolver.LookupIPAddr(ctx, host)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, err
	}
	if len(addresses) == 0 {
		return nil, elapsed, errors.New("DNS returned no addresses")
	}
	sort.SliceStable(addresses, func(i, j int) bool {
		iV4 := addresses[i].IP.To4() != nil
		jV4 := addresses[j].IP.To4() != nil
		if preferredIP == "4" && iV4 != jV4 {
			return iV4
		}
		if preferredIP == "6" && iV4 != jV4 {
			return !iV4
		}
		return false
	})
	return addresses, elapsed, nil
}

func addressFingerprint(addresses []net.IPAddr) (string, string) {
	if len(addresses) == 0 {
		return "", ""
	}
	values := make([]string, 0, len(addresses))
	family := "ipv6"
	for _, address := range addresses {
		values = append(values, address.IP.String())
		if address.IP.To4() != nil {
			family = "ipv4"
		}
	}
	sort.Strings(values)
	sum := sha256.Sum256([]byte(strings.Join(values, ",")))
	return hex.EncodeToString(sum[:6]), family
}

func probeErrorCode(err error) string {
	if err == nil {
		return ""
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return probeErrorCode(urlErr.Err)
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "tls"), strings.Contains(text, "certificate"):
		return "tls_error"
	case strings.Contains(text, "connect"), strings.Contains(text, "dial"):
		return "connect_error"
	default:
		return "probe_error"
	}
}

func performProbe(pingType, target string, rawOptions v2.ProbeOptions) (int, *v2.ProbeResultDetails, error) {
	options := normalizeProbeOptions(rawOptions, pingType)
	switch pingType {
	case "icmp":
		return performICMPProbe(target, options)
	case "tcp":
		return performTCPProbe(target, options)
	case "http":
		return performHTTPProbe(target, options)
	default:
		details := &v2.ProbeResultDetails{ErrorCode: "unsupported_probe_type"}
		return -1, details, errors.New("unsupported ping type")
	}
}

func performICMPProbe(target string, options normalizedProbeOptions) (int, *v2.ProbeResultDetails, error) {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	host = strings.Trim(host, "[]")

	ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
	defer cancel()
	addresses, dnsDuration, err := lookupProbeAddresses(ctx, taskResolver(options.dnsServer), host, options.preferredIP)
	details := &v2.ProbeResultDetails{
		SamplesSent: options.sampleCount,
		PacketSize:  options.packetSize,
		DNSMS:       float64(dnsDuration.Microseconds()) / 1000,
		DNSMode:     "system",
	}
	if options.dnsServer != "" {
		details.DNSMode = "custom"
	}
	if err != nil {
		details.LossRatio = 1
		details.ErrorCode = probeErrorCode(err)
		return -1, details, err
	}
	details.ResolvedAddressHash, details.ResolvedAddressFamily = addressFingerprint(addresses)

	pinger, err := ping.NewPinger(addresses[0].IP.String())
	if err != nil {
		details.LossRatio = 1
		details.ErrorCode = "probe_error"
		return -1, details, err
	}
	pinger.Count = options.sampleCount
	pinger.Interval = 200 * time.Millisecond
	pinger.Timeout = options.timeout
	pinger.Size = options.packetSize
	pinger.SetPrivileged(true)
	if err := pinger.Run(); err != nil {
		details.LossRatio = 1
		details.ErrorCode = probeErrorCode(err)
		return -1, details, err
	}

	stats := pinger.Statistics()
	details.SamplesSent = stats.PacketsSent
	details.SamplesReceived = stats.PacketsRecv
	details.LossRatio = stats.PacketLoss / 100
	details.Reachable = stats.PacketsRecv > 0
	if !details.Reachable {
		details.ErrorCode = "no_reply"
		return -1, details, errors.New("no packets received")
	}
	details.MinLatencyMS = float64(stats.MinRtt.Microseconds()) / 1000
	details.MaxLatencyMS = float64(stats.MaxRtt.Microseconds()) / 1000
	details.AverageLatencyMS = float64(stats.AvgRtt.Microseconds()) / 1000
	details.JitterMS = float64(stats.StdDevRtt.Microseconds()) / 1000
	return int(stats.AvgRtt.Milliseconds()), details, nil
}

func splitProbeTarget(target, defaultPort string) (string, string) {
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		return strings.Trim(host, "[]"), port
	}
	return strings.Trim(target, "[]"), defaultPort
}

func performTCPProbe(target string, options normalizedProbeOptions) (int, *v2.ProbeResultDetails, error) {
	host, port := splitProbeTarget(target, "80")
	resolver := taskResolver(options.dnsServer)
	details := &v2.ProbeResultDetails{
		SamplesSent: options.sampleCount,
		DNSMode:     "system",
	}
	if options.dnsServer != "" {
		details.DNSMode = "custom"
	}

	var latencies []float64
	var dnsTotal, connectTotal time.Duration
	var lastErr error
	for i := 0; i < options.sampleCount; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), options.timeout)
		addresses, dnsDuration, err := lookupProbeAddresses(ctx, resolver, host, options.preferredIP)
		dnsTotal += dnsDuration
		if err != nil {
			lastErr = err
			cancel()
			continue
		}
		details.ResolvedAddressHash, details.ResolvedAddressFamily = addressFingerprint(addresses)
		start := time.Now()
		var conn net.Conn
		for _, address := range addresses {
			dialer := &net.Dialer{Timeout: options.timeout}
			conn, err = dialer.DialContext(ctx, "tcp", net.JoinHostPort(address.IP.String(), port))
			if err == nil {
				break
			}
		}
		elapsed := time.Since(start)
		connectTotal += elapsed
		if err != nil {
			lastErr = err
			cancel()
			continue
		}
		details.TCPRetransmissions += tcpRetransmissions(conn)
		_ = conn.Close()
		cancel()
		latencies = append(latencies, float64(elapsed.Microseconds())/1000)
	}

	finalizeLatencyDetails(details, latencies)
	details.SamplesReceived = len(latencies)
	details.LossRatio = float64(options.sampleCount-len(latencies)) / float64(options.sampleCount)
	details.DNSMS = durationAverageMS(dnsTotal, options.sampleCount)
	details.ConnectMS = durationAverageMS(connectTotal, maxInt(len(latencies), 1))
	details.Reachable = len(latencies) > 0
	if !details.Reachable {
		details.ErrorCode = probeErrorCode(lastErr)
		return -1, details, lastErr
	}
	return int(details.AverageLatencyMS), details, nil
}

type httpProbeSample struct {
	latencyMS       float64
	dns             time.Duration
	connect         time.Duration
	tls             time.Duration
	ttfb            time.Duration
	statusCode      int
	statusOK        bool
	retransmissions int
	addressHash     string
	addressFamily   string
}

type httpProbeTrace struct {
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

func (trace *httpProbeTrace) addDNS(duration time.Duration, addresses []net.IPAddr) {
	trace.mu.Lock()
	defer trace.mu.Unlock()
	trace.dns += duration
	trace.addressHash, trace.addressFamily = addressFingerprint(addresses)
}

func performHTTPSample(target string, options normalizedProbeOptions) (httpProbeSample, error) {
	resolver := taskResolver(options.dnsServer)
	traceState := &httpProbeTrace{}
	transport := &http.Transport{
		DisableKeepAlives:   true,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: options.timeout,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			addresses, dnsDuration, err := lookupProbeAddresses(ctx, resolver, host, options.preferredIP)
			traceState.addDNS(dnsDuration, addresses)
			if err != nil {
				return nil, err
			}
			var lastErr error
			for _, resolved := range addresses {
				dialer := &net.Dialer{Timeout: options.timeout, KeepAlive: 30 * time.Second}
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(resolved.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{Timeout: options.timeout, Transport: transport}
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return httpProbeSample{}, err
	}
	request.Header.Set("User-Agent", "Komari-Network-Probe/1.0")
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
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), clientTrace))

	start := time.Now()
	traceState.mu.Lock()
	traceState.requestStart = start
	traceState.mu.Unlock()
	response, err := client.Do(request)
	total := time.Since(start)
	if err != nil {
		return httpProbeSample{}, err
	}

	traceState.mu.Lock()
	currentConn := traceState.currentConn
	traceState.mu.Unlock()
	retransmissions := tcpRetransmissions(currentConn)

	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()

	traceState.mu.Lock()
	defer traceState.mu.Unlock()
	statusOK := response.StatusCode >= 200 && response.StatusCode < 400
	if len(options.validStatusCodes) > 0 {
		_, statusOK = options.validStatusCodes[response.StatusCode]
	}
	ttfb := time.Duration(0)
	if !traceState.firstByteAt.IsZero() {
		ttfb = traceState.firstByteAt.Sub(traceState.requestStart)
	}
	return httpProbeSample{
		latencyMS:       float64(total.Microseconds()) / 1000,
		dns:             traceState.dns,
		connect:         traceState.connect,
		tls:             traceState.tls,
		ttfb:            ttfb,
		statusCode:      response.StatusCode,
		statusOK:        statusOK,
		retransmissions: retransmissions,
		addressHash:     traceState.addressHash,
		addressFamily:   traceState.addressFamily,
	}, nil
}

func performHTTPProbe(target string, options normalizedProbeOptions) (int, *v2.ProbeResultDetails, error) {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}
	if _, err := url.ParseRequestURI(target); err != nil {
		details := &v2.ProbeResultDetails{ErrorCode: "invalid_target"}
		return -1, details, err
	}

	details := &v2.ProbeResultDetails{
		SamplesSent: options.sampleCount,
		DNSMode:     "system",
	}
	if options.dnsServer != "" {
		details.DNSMode = "custom"
	}
	var latencies []float64
	var dnsTotal, connectTotal, tlsTotal, ttfbTotal time.Duration
	var statusOKCount int
	var lastErr error
	for i := 0; i < options.sampleCount; i++ {
		sample, err := performHTTPSample(target, options)
		if err != nil {
			lastErr = err
			continue
		}
		latencies = append(latencies, sample.latencyMS)
		dnsTotal += sample.dns
		connectTotal += sample.connect
		tlsTotal += sample.tls
		ttfbTotal += sample.ttfb
		details.HTTPStatusCode = sample.statusCode
		details.TCPRetransmissions += sample.retransmissions
		details.ResolvedAddressHash = sample.addressHash
		details.ResolvedAddressFamily = sample.addressFamily
		if sample.statusOK {
			statusOKCount++
		}
	}

	finalizeLatencyDetails(details, latencies)
	details.SamplesReceived = len(latencies)
	details.LossRatio = float64(options.sampleCount-len(latencies)) / float64(options.sampleCount)
	details.Reachable = len(latencies) > 0
	if len(latencies) > 0 {
		details.DNSMS = durationAverageMS(dnsTotal, len(latencies))
		details.ConnectMS = durationAverageMS(connectTotal, len(latencies))
		details.TLSMS = durationAverageMS(tlsTotal, len(latencies))
		details.TTFBMS = durationAverageMS(ttfbTotal, len(latencies))
		details.HTTPStatusOKRatio = float64(statusOKCount) / float64(len(latencies))
		return int(details.AverageLatencyMS), details, nil
	}
	details.ErrorCode = probeErrorCode(lastErr)
	return -1, details, lastErr
}

func durationAverageMS(total time.Duration, count int) float64 {
	if count <= 0 {
		return 0
	}
	return float64(total.Microseconds()) / 1000 / float64(count)
}

func finalizeLatencyDetails(details *v2.ProbeResultDetails, latencies []float64) {
	if len(latencies) == 0 {
		return
	}
	sorted := append([]float64(nil), latencies...)
	sort.Float64s(sorted)
	var total float64
	for _, latency := range sorted {
		total += latency
	}
	average := total / float64(len(sorted))
	var variance float64
	for _, latency := range sorted {
		delta := latency - average
		variance += delta * delta
	}
	details.MinLatencyMS = sorted[0]
	details.MaxLatencyMS = sorted[len(sorted)-1]
	details.AverageLatencyMS = average
	details.JitterMS = math.Sqrt(variance / float64(len(sorted)))
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func validateProbeOptions(raw v2.ProbeOptions, pingType string) error {
	if raw.SampleCount < 0 || raw.SampleCount > maxProbeSamples {
		return fmt.Errorf("sample_count must be between 1 and %d", maxProbeSamples)
	}
	if raw.TimeoutMS < 0 || raw.TimeoutMS > maxProbeTimeoutMS {
		return fmt.Errorf("timeout_ms must be between 1 and %d", maxProbeTimeoutMS)
	}
	if pingType == "icmp" && raw.PacketSize != 0 && (raw.PacketSize < 24 || raw.PacketSize > maxICMPPacketSize) {
		return fmt.Errorf("packet_size must be between 24 and %d", maxICMPPacketSize)
	}
	return nil
}
