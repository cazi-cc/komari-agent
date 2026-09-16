package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/ws"
)

const (
	maxTCPQualityTargets  = 512
	maxTCPQualityParallel = 4
)

var (
	tcpQualityRunning     sync.Map
	tcpQualityIPv6ForceL2 atomic.Bool
	npingRTTRE            = regexp.MustCompile(`(?m)^RCVD[^\r\n]*\brtt=([0-9]+(?:\.[0-9]+)?)ms\b`)
	npingTCPEventRE       = regexp.MustCompile(`^(SENT|RCVD)\s+\(([0-9]+(?:\.[0-9]+)?)s\)\s+TCP\b`)
)

type npingIPv6Route struct {
	Interface      string
	SourceIP       string
	SourceMAC      string
	DestinationMAC string
}

func NewTCPQualityTask(conn *ws.SafeConn, params v2.TCPQualityParams) {
	if err := validateTCPQualityParams(params); err != nil {
		return
	}
	taskKey := strconv.FormatUint(uint64(params.TaskID), 10)
	if _, loaded := tcpQualityRunning.LoadOrStore(taskKey, params.RunID); loaded {
		uploadTCPQualityResult(conn, v2.TCPQualityResultParams{
			TaskID:          params.TaskID,
			RunID:           params.RunID,
			CatalogRevision: params.CatalogRevision,
			Results:         unavailableTCPQualityResults(params, "task_already_running"),
			ErrorCode:       "task_already_running",
			FinishedAt:      time.Now().UTC(),
		})
		return
	}
	defer tcpQualityRunning.Delete(taskKey)

	heavyProbeGate.run(fmt.Sprintf("tcp-quality:%d", params.TaskID), func() {
		results, errorCode := performTCPQualityTask(params)
		uploadTCPQualityResult(conn, v2.TCPQualityResultParams{
			TaskID:          params.TaskID,
			RunID:           params.RunID,
			CatalogRevision: params.CatalogRevision,
			Results:         results,
			ErrorCode:       errorCode,
			FinishedAt:      time.Now().UTC(),
		})
	})
}

func validateTCPQualityParams(params v2.TCPQualityParams) error {
	if params.TaskID == 0 || !validTCPQualityID(params.RunID, 64) || !validTCPQualityID(params.CatalogRevision, 64) {
		return errors.New("invalid TCP quality task identity")
	}
	if len(params.Targets) == 0 || len(params.Targets) > maxTCPQualityTargets {
		return errors.New("invalid TCP quality target count")
	}
	if params.StandardPackets < 10 || params.StandardPackets > 200 ||
		params.DelayMS < 50 || params.DelayMS > 5000 ||
		params.TimeoutMS < 500 || params.TimeoutMS > 15000 {
		return errors.New("invalid TCP quality probe limits")
	}
	if params.LargeEnabled && (params.LargePackets < 10 || params.LargePackets > 100) {
		return errors.New("invalid legacy TCP quality payload probe limits")
	}
	if params.ExperimentalEnabled && (params.ExperimentalPackets < 10 || params.ExperimentalPackets > 100 ||
		params.ExperimentalControlPackets < 3 || params.ExperimentalControlPackets > 20) {
		return errors.New("invalid experimental TCP quality probe limits")
	}
	seen := make(map[string]struct{}, len(params.Targets))
	for _, target := range params.Targets {
		ip := net.ParseIP(strings.TrimSpace(target.Address))
		if !validTCPQualityID(target.Key, 64) || ip == nil || target.Port < 1 || target.Port > 65535 {
			return errors.New("invalid TCP quality target")
		}
		if target.Fingerprint != "" && !validTCPQualityID(target.Fingerprint, 64) {
			return errors.New("invalid TCP quality target fingerprint")
		}
		version := 6
		if ip.To4() != nil {
			version = 4
		}
		if target.IPVersion != version {
			return errors.New("TCP quality target family mismatch")
		}
		if _, exists := seen[target.Key]; exists {
			return errors.New("duplicate TCP quality target")
		}
		seen[target.Key] = struct{}{}
	}
	return nil
}

func validTCPQualityID(value string, maximum int) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maximum {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}

func performTCPQualityTask(params v2.TCPQualityParams) ([]v2.TCPQualityTargetResult, string) {
	if runtime.GOOS != "linux" {
		return unavailableTCPQualityResults(params, "unsupported_platform"), "unsupported_platform"
	}
	npingPath, err := exec.LookPath("nping")
	if err != nil {
		return unavailableTCPQualityResults(params, "nping_unavailable"), "nping_unavailable"
	}
	parallel := params.MaxParallel
	if parallel < 1 {
		parallel = 1
	}
	if parallel > maxTCPQualityParallel {
		parallel = maxTCPQualityParallel
	}
	if params.ExperimentalEnabled && params.ExperimentalDue {
		parallel = 1
	}
	type indexedResults struct {
		index   int
		results []v2.TCPQualityTargetResult
	}
	semaphore := make(chan struct{}, parallel)
	output := make(chan indexedResults, len(params.Targets))
	var wait sync.WaitGroup
	for index, target := range params.Targets {
		index, target := index, target
		wait.Add(1)
		go func() {
			defer wait.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			targetResults := []v2.TCPQualityTargetResult{
				runTCPQualityMode(npingPath, target, "standard", params.StandardPackets, params.DelayMS, params.TimeoutMS),
			}
			if params.LargeEnabled {
				targetResults = append(targetResults,
					runTCPQualityMode(npingPath, target, "large", params.LargePackets, params.DelayMS, params.TimeoutMS))
			}
			if params.ExperimentalEnabled && params.ExperimentalDue {
				targetResults = append(targetResults, runTCPQualityExperimentalModes(npingPath, target, params.ExperimentalPackets,
					params.ExperimentalControlPackets, params.DelayMS, params.TimeoutMS)...)
			}
			output <- indexedResults{index: index, results: targetResults}
		}()
	}
	wait.Wait()
	close(output)
	ordered := make([][]v2.TCPQualityTargetResult, len(params.Targets))
	for item := range output {
		ordered[item.index] = item.results
	}
	results := make([]v2.TCPQualityTargetResult, 0, len(params.Targets)*4)
	for _, group := range ordered {
		results = append(results, group...)
	}
	return results, ""
}

func unavailableTCPQualityResults(params v2.TCPQualityParams, code string) []v2.TCPQualityTargetResult {
	results := make([]v2.TCPQualityTargetResult, 0, len(params.Targets)*4)
	for _, target := range params.Targets {
		results = append(results, v2.TCPQualityTargetResult{TargetKey: target.Key, TargetFingerprint: target.Fingerprint, Mode: "standard", ErrorCode: code})
		if params.LargeEnabled {
			results = append(results, v2.TCPQualityTargetResult{TargetKey: target.Key, TargetFingerprint: target.Fingerprint, Mode: "large", ErrorCode: code})
		}
		if params.ExperimentalEnabled && params.ExperimentalDue {
			for _, mode := range []struct {
				name    string
				payload int
			}{{"experimental_standard", 0}, {"payload_300", 300}, {"payload_1050", 1050}} {
				results = append(results, v2.TCPQualityTargetResult{TargetKey: target.Key, TargetFingerprint: target.Fingerprint,
					Mode: mode.name, PayloadBytes: mode.payload, ErrorCode: code})
			}
		}
	}
	return results
}

func runTCPQualityExperimentalModes(npingPath string, target v2.TCPQualityTarget, count, controlCount, delayMS, timeoutMS int) []v2.TCPQualityTargetResult {
	type modeSpec struct {
		name    string
		payload int
	}
	modes := []modeSpec{{"experimental_standard", 0}, {"payload_300", 300}, {"payload_1050", 1050}}
	controlTarget, controlErr := resolveTCPQualityControlTarget(target.IPVersion)
	controlLatencies := []float64(nil)
	controlCode := ""
	if controlErr == nil {
		controlLatencies, controlCode = runTCPQualityIndependentSeries(npingPath, controlTarget, 1050, controlCount, delayMS, timeoutMS)
	} else {
		controlCode = "control_dns_error"
	}
	controlReceived := len(controlLatencies)
	controlLoss := 1.0
	if controlCount > 0 {
		controlLoss = float64(controlCount-controlReceived) / float64(controlCount)
	}
	environmentLimited := controlCode != "" && controlReceived == 0 || controlLoss >= 0.80
	if environmentLimited {
		results := make([]v2.TCPQualityTargetResult, 0, len(modes))
		for _, mode := range modes {
			results = append(results, v2.TCPQualityTargetResult{
				TargetKey: target.Key, TargetFingerprint: target.Fingerprint, Mode: mode.name, PayloadBytes: mode.payload,
				ControlSamplesSent: controlCount, ControlSamplesReceived: controlReceived, ControlLossRatio: controlLoss,
				EnvironmentLimited: true, ErrorCode: "environment_limited",
			})
		}
		return results
	}

	latencies := make(map[string][]float64, len(modes))
	lastErrors := make(map[string]string, len(modes))
	var route *npingIPv6Route
	if target.IPVersion == 6 {
		route, _ = discoverNpingIPv6Route(target.Address)
	}
	for sample := 0; sample < count; sample++ {
		for offset := 0; offset < len(modes); offset++ {
			mode := modes[(sample+offset)%len(modes)]
			value, code := runNpingIndependentSample(npingPath, target, mode.payload, timeoutMS, route)
			if value >= 0 {
				latencies[mode.name] = append(latencies[mode.name], value)
			}
			if code != "" {
				lastErrors[mode.name] = code
			}
			if delayMS > 0 {
				time.Sleep(time.Duration(delayMS) * time.Millisecond)
			}
		}
	}
	results := make([]v2.TCPQualityTargetResult, 0, len(modes))
	for _, mode := range modes {
		result := buildTCPQualityResult(target, mode.name, mode.payload, count, latencies[mode.name], lastErrors[mode.name])
		result.ControlSamplesSent = controlCount
		result.ControlSamplesReceived = controlReceived
		result.ControlLossRatio = controlLoss
		results = append(results, result)
	}
	return results
}

func resolveTCPQualityControlTarget(ipVersion int) (v2.TCPQualityTarget, error) {
	network := "ip4"
	if ipVersion == 6 {
		network = "ip6"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(ctx, network, "www.cloudflare.com")
	if err != nil || len(addresses) == 0 {
		return v2.TCPQualityTarget{}, errors.New("control target is unavailable")
	}
	for _, address := range addresses {
		if address == nil || (ipVersion == 4 && address.To4() == nil) || (ipVersion == 6 && address.To4() != nil) {
			continue
		}
		return v2.TCPQualityTarget{Key: "control", Address: address.String(), Port: 443, IPVersion: ipVersion}, nil
	}
	return v2.TCPQualityTarget{}, errors.New("control target family is unavailable")
}

func runTCPQualityIndependentSeries(npingPath string, target v2.TCPQualityTarget, payloadSize, count, delayMS, timeoutMS int) ([]float64, string) {
	latencies := make([]float64, 0, count)
	lastError := ""
	var route *npingIPv6Route
	if target.IPVersion == 6 {
		route, _ = discoverNpingIPv6Route(target.Address)
	}
	for sample := 0; sample < count; sample++ {
		value, code := runNpingIndependentSample(npingPath, target, payloadSize, timeoutMS, route)
		if value >= 0 {
			latencies = append(latencies, value)
		}
		if code != "" {
			lastError = code
		}
		if delayMS > 0 && sample+1 < count {
			time.Sleep(time.Duration(delayMS) * time.Millisecond)
		}
	}
	return latencies, lastError
}

func runNpingIndependentSample(npingPath string, target v2.TCPQualityTarget, payloadSize, timeoutMS int, route *npingIPv6Route) (float64, string) {
	sourcePort, sequence := randomTCPQualityTuple()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMS)*time.Millisecond+5*time.Second)
	defer cancel()
	args := buildNpingBatchArgs(target, payloadSize, 1, 0, route)
	last := len(args) - 1
	args = append(args[:last], append([]string{"-g", strconv.Itoa(sourcePort), "--seq", strconv.FormatUint(uint64(sequence), 10)}, args[last:]...)...)
	output, err := exec.CommandContext(ctx, npingPath, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return -1, "timeout"
	}
	latencies, received := parseNpingBatchOutput(string(output))
	if received == 0 || len(latencies) == 0 {
		if err != nil {
			return -1, "nping_error"
		}
		return -1, "no_response"
	}
	return latencies[0], ""
}

func randomTCPQualityTuple() (int, uint32) {
	var raw [6]byte
	if _, err := rand.Read(raw[:]); err != nil {
		now := uint64(time.Now().UnixNano())
		return 20000 + int(now%40000), uint32(now >> 16)
	}
	sequence := binary.BigEndian.Uint32(raw[2:]) & 0x7ffffffe
	if sequence == 0 {
		sequence = 1
	}
	return 20000 + int(binary.BigEndian.Uint16(raw[:2]))%40000, sequence
}

func buildTCPQualityResult(target v2.TCPQualityTarget, mode string, payloadBytes, count int, latencies []float64, lastError string) v2.TCPQualityTargetResult {
	result := v2.TCPQualityTargetResult{
		TargetKey: target.Key, TargetFingerprint: target.Fingerprint, Mode: mode, PayloadBytes: payloadBytes,
		SamplesSent: count, SamplesReceived: len(latencies),
	}
	if count > 0 {
		result.LossRatio = float64(count-len(latencies)) / float64(count)
	}
	if len(latencies) == 0 {
		if lastError == "" {
			lastError = "no_response"
		}
		result.ErrorCode = lastError
		return result
	}
	sort.Float64s(latencies)
	result.MinLatencyMS = latencies[0]
	result.MaxLatencyMS = latencies[len(latencies)-1]
	result.P50LatencyMS = floatQuantile(latencies, 0.50)
	result.P95LatencyMS = floatQuantile(latencies, 0.95)
	for _, latency := range latencies {
		result.AverageLatencyMS += latency
	}
	result.AverageLatencyMS /= float64(len(latencies))
	if len(latencies) < count {
		result.ErrorCode = "partial_loss"
	}
	return result
}

func runTCPQualityMode(npingPath string, target v2.TCPQualityTarget, mode string, count, delayMS, timeoutMS int) v2.TCPQualityTargetResult {
	result := v2.TCPQualityTargetResult{
		TargetKey: target.Key, TargetFingerprint: target.Fingerprint,
		Mode: mode, SamplesSent: count,
	}
	latencies := make([]float64, 0, count)
	lastError := ""
	if mode == "large" {
		smallCount := count / 4
		largeCount := count - smallCount
		for _, batch := range []struct {
			payload int
			count   int
		}{
			{payload: 1050, count: largeCount},
			{payload: 300, count: smallCount},
		} {
			if batch.count == 0 {
				continue
			}
			values, code := runNpingBatch(npingPath, target, batch.payload, batch.count, delayMS, timeoutMS)
			latencies = append(latencies, values...)
			if code != "" {
				lastError = code
			}
		}
	} else {
		latencies, lastError = runNpingBatch(npingPath, target, 0, count, delayMS, timeoutMS)
	}
	result.SamplesReceived = len(latencies)
	result.LossRatio = float64(count-len(latencies)) / float64(count)
	if len(latencies) == 0 {
		if lastError == "" {
			lastError = "no_response"
		}
		result.ErrorCode = lastError
		return result
	}
	sort.Float64s(latencies)
	result.MinLatencyMS = latencies[0]
	result.MaxLatencyMS = latencies[len(latencies)-1]
	result.P50LatencyMS = floatQuantile(latencies, 0.50)
	result.P95LatencyMS = floatQuantile(latencies, 0.95)
	total := 0.0
	for _, latency := range latencies {
		total += latency
	}
	result.AverageLatencyMS = total / float64(len(latencies))
	if len(latencies) < count {
		result.ErrorCode = "partial_loss"
	}
	return result
}

func runNpingBatch(npingPath string, target v2.TCPQualityTarget, payloadSize, count, delayMS, timeoutMS int) ([]float64, string) {
	if target.IPVersion == 6 && tcpQualityIPv6ForceL2.Load() {
		if route, err := discoverNpingIPv6Route(target.Address); err == nil {
			return runNpingBatchAttempt(npingPath, target, payloadSize, count, delayMS, timeoutMS, route)
		}
	}

	latencies, code := runNpingBatchAttempt(npingPath, target, payloadSize, count, delayMS, timeoutMS, nil)
	if target.IPVersion != 6 || len(latencies) > 0 {
		return latencies, code
	}

	route, err := discoverNpingIPv6Route(target.Address)
	if err != nil {
		return latencies, code
	}
	retryLatencies, retryCode := runNpingBatchAttempt(npingPath, target, payloadSize, count, delayMS, timeoutMS, route)
	if len(retryLatencies) > 0 {
		tcpQualityIPv6ForceL2.Store(true)
	}
	return retryLatencies, retryCode
}

func runNpingBatchAttempt(npingPath string, target v2.TCPQualityTarget, payloadSize, count, delayMS, timeoutMS int, route *npingIPv6Route) ([]float64, string) {
	timeout := time.Duration(count*delayMS+timeoutMS)*time.Millisecond + 5*time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := buildNpingBatchArgs(target, payloadSize, count, delayMS, route)
	output, err := exec.CommandContext(ctx, npingPath, args...).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, "timeout"
	}
	latencies, received := parseNpingBatchOutput(string(output))
	if received == 0 {
		if err != nil {
			return nil, "nping_error"
		}
		return nil, "no_response"
	}
	if len(latencies) == 0 {
		return nil, "parse_error"
	}
	if len(latencies) > count {
		latencies = latencies[:count]
	}
	if len(latencies) < received {
		return latencies, "partial_parse"
	}
	return latencies, ""
}

func buildNpingBatchArgs(target v2.TCPQualityTarget, payloadSize, count, delayMS int, route *npingIPv6Route) []string {
	args := make([]string, 0, 24)
	if target.IPVersion == 6 {
		args = append(args, "-6")
		if route != nil {
			args = append(args,
				"-e", route.Interface,
				"-S", route.SourceIP,
				"--source-mac", route.SourceMAC,
				"--dest-mac", route.DestinationMAC,
			)
		}
	}
	args = append(args,
		"--tcp", "-p", strconv.Itoa(target.Port), "--flags", "syn",
		"-c", strconv.Itoa(count), "--delay", strconv.Itoa(delayMS)+"ms",
	)
	if route == nil {
		args = append(args, "--privileged")
	}
	if payloadSize > 0 {
		args = append(args, "--data-length", strconv.Itoa(payloadSize))
	}
	return append(args, target.Address)
}

func discoverNpingIPv6Route(target string) (*npingIPv6Route, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, "ip", "-6", "route", "get", target).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("resolve IPv6 route: %w", err)
	}
	interfaceName, sourceIP, nextHop := parseNpingIPv6Route(string(output))
	if interfaceName == "" {
		return nil, errors.New("IPv6 route has no interface")
	}
	if sourceIP == "" {
		sourceIP = interfaceIPv6Source(interfaceName)
	}
	source := net.ParseIP(sourceIP)
	if source == nil || source.To4() != nil || source.IsUnspecified() || source.IsLinkLocalUnicast() {
		return nil, errors.New("IPv6 route has no usable source address")
	}
	if nextHop == "" {
		nextHop = target
	}

	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil || !validNpingMAC(networkInterface.HardwareAddr.String()) {
		return nil, errors.New("IPv6 route has no usable source MAC")
	}
	destinationMAC := resolveNpingIPv6Neighbor(ctx, interfaceName, nextHop)
	if destinationMAC == "" {
		return nil, errors.New("IPv6 route has no reachable next-hop MAC")
	}
	return &npingIPv6Route{
		Interface:      interfaceName,
		SourceIP:       source.String(),
		SourceMAC:      networkInterface.HardwareAddr.String(),
		DestinationMAC: destinationMAC,
	}, nil
}

func parseNpingIPv6Route(output string) (interfaceName, sourceIP, nextHop string) {
	fields := strings.Fields(output)
	for index := 0; index+1 < len(fields); index++ {
		switch fields[index] {
		case "dev":
			if interfaceName == "" {
				interfaceName = fields[index+1]
			}
		case "src":
			if sourceIP == "" {
				sourceIP = strings.Split(fields[index+1], "%")[0]
			}
		case "via":
			if nextHop == "" {
				nextHop = strings.Split(fields[index+1], "%")[0]
			}
		}
	}
	return interfaceName, sourceIP, nextHop
}

func interfaceIPv6Source(interfaceName string) string {
	networkInterface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ""
	}
	addresses, err := networkInterface.Addrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() == nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip.String()
		}
	}
	return ""
}

func resolveNpingIPv6Neighbor(ctx context.Context, interfaceName, nextHop string) string {
	readNeighbor := func() string {
		output, err := exec.CommandContext(ctx, "ip", "-6", "neigh", "show", nextHop, "dev", interfaceName).CombinedOutput()
		if err != nil {
			return ""
		}
		return parseNpingIPv6Neighbor(string(output))
	}
	if destinationMAC := readNeighbor(); destinationMAC != "" {
		return destinationMAC
	}
	if _, err := exec.LookPath("ping"); err == nil {
		_ = exec.CommandContext(ctx, "ping", "-6", "-c", "1", "-W", "1", "-I", interfaceName, nextHop).Run()
	}
	return readNeighbor()
}

func parseNpingIPv6Neighbor(output string) string {
	fields := strings.Fields(output)
	for index := 0; index+1 < len(fields); index++ {
		if fields[index] == "lladdr" && validNpingMAC(fields[index+1]) {
			return strings.ToLower(fields[index+1])
		}
	}
	return ""
}

func validNpingMAC(value string) bool {
	hardwareAddress, err := net.ParseMAC(value)
	return err == nil && len(hardwareAddress) == 6
}

func parseNpingBatchOutput(output string) ([]float64, int) {
	matches := npingRTTRE.FindAllStringSubmatch(output, -1)
	latencies := make([]float64, 0, len(matches))
	for _, match := range matches {
		latency, err := strconv.ParseFloat(match[1], 64)
		if err != nil || math.IsNaN(latency) || math.IsInf(latency, 0) || latency < 0 {
			continue
		}
		latencies = append(latencies, latency)
	}
	if len(latencies) > 0 {
		return latencies, len(latencies)
	}

	// Nping 0.7.93 no longer prints rtt=... on RCVD lines. It calculates
	// summary RTT against the most recent unmatched send, so mirror that
	// behavior while counting only TCP responses.
	pendingSends := make([]float64, 0)
	for _, line := range strings.Split(output, "\n") {
		match := npingTCPEventRE.FindStringSubmatch(strings.TrimSpace(line))
		if len(match) != 3 {
			continue
		}
		eventTime, err := strconv.ParseFloat(match[2], 64)
		if err != nil || math.IsNaN(eventTime) || math.IsInf(eventTime, 0) || eventTime < 0 {
			continue
		}
		if match[1] == "SENT" {
			pendingSends = append(pendingSends, eventTime)
			continue
		}
		if len(pendingSends) == 0 {
			continue
		}
		last := len(pendingSends) - 1
		latency := (eventTime - pendingSends[last]) * 1000
		pendingSends = pendingSends[:last]
		if latency < 0 || math.IsNaN(latency) || math.IsInf(latency, 0) {
			continue
		}
		latencies = append(latencies, latency)
	}
	return latencies, len(latencies)
}

func floatQuantile(sortedValues []float64, percentile float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}
	position := float64(len(sortedValues)-1) * percentile
	lower, upper := int(math.Floor(position)), int(math.Ceil(position))
	if lower == upper {
		return sortedValues[lower]
	}
	fraction := position - float64(lower)
	return sortedValues[lower]*(1-fraction) + sortedValues[upper]*fraction
}

func uploadTCPQualityResult(conn *ws.SafeConn, params v2.TCPQualityResultParams) {
	payload := v2.BuildTCPQualityResultPayload(params)
	if conn == nil {
		if err := postV2RPC(payload); err != nil {
			fmt.Printf("Failed to upload TCP quality result over POST: %v\n", err)
		}
		return
	}
	if err := conn.WriteJSON(payload); err != nil {
		fmt.Printf("Failed to upload TCP quality result over WebSocket: %v\n", err)
	}
}
