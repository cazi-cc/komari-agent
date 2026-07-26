package v2

import (
	"encoding/json"
	"time"

	v1 "github.com/komari-monitor/komari-agent/protocol/v1"
)

const (
	Version                     = "2.0"
	MethodAgentReport           = "agent.report"
	MethodAgentBasicInfo        = "agent.basicInfo"
	MethodAgentPingResult       = "agent.pingResult"
	MethodAgentTaskResult       = "agent.taskResult"
	MethodAgentExec             = "agent.exec"
	MethodAgentPing             = "agent.ping"
	MethodAgentTCPQuality       = "agent.tcpQuality"
	MethodAgentTCPQualityResult = "agent.tcpQualityResult"
	MethodAgentMessage          = "agent.message"
	MethodAgentEvent            = "agent.event"
	MethodAgentTerminal         = "agent.terminal.request"
	MethodAgentPull             = "agent.pull"
)

type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      interface{} `json:"id,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id,omitempty"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
}

type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type Event struct {
	ID        string      `json:"id"`
	Method    string      `json:"method"`
	Params    interface{} `json:"params,omitempty"`
	CreatedAt string      `json:"created_at,omitempty"`
	ExpiresAt string      `json:"expires_at,omitempty"`
}

type EventResult struct {
	Status string  `json:"status,omitempty"`
	Events []Event `json:"events,omitempty"`
}

func NewNotification(method string, params interface{}) []byte {
	payload, _ := json.Marshal(Request{JSONRPC: Version, Method: method, Params: params})
	return payload
}

func NewRequest(id interface{}, method string, params interface{}) []byte {
	payload, _ := json.Marshal(Request{JSONRPC: Version, Method: method, Params: params, ID: id})
	return payload
}

func BuildReportPayload(report v1.ReportPayload) []byte {
	return NewNotification(MethodAgentReport, reportParams{Report: json.RawMessage(report)})
}

func BuildReportRequest(id interface{}, report v1.ReportPayload, ackEventIDs []string) []byte {
	return NewRequest(id, MethodAgentReport, reportParams{Report: json.RawMessage(report), AckEventIDs: ackEventIDs})
}

func BuildBasicInfoPayload(info map[string]interface{}) []byte {
	return NewNotification(MethodAgentBasicInfo, map[string]interface{}{"info": info})
}

type reportParams struct {
	Report      json.RawMessage `json:"report"`
	AckEventIDs []string        `json:"ack_event_ids,omitempty"`
}

type ProbeOptions struct {
	PacketSize       int    `json:"packet_size,omitempty"`
	SampleCount      int    `json:"sample_count,omitempty"`
	TimeoutMS        int    `json:"timeout_ms,omitempty"`
	DNSServer        string `json:"dns_server,omitempty"`
	PreferredIP      string `json:"preferred_ip,omitempty"`
	ValidStatusCodes []int  `json:"valid_status_codes,omitempty"`
}

type ProbeResultDetails struct {
	Reachable             bool    `json:"reachable"`
	SamplesSent           int     `json:"samples_sent,omitempty"`
	SamplesReceived       int     `json:"samples_received,omitempty"`
	LossRatio             float64 `json:"loss_ratio,omitempty"`
	PacketSize            int     `json:"packet_size,omitempty"`
	MinLatencyMS          float64 `json:"min_latency_ms,omitempty"`
	MaxLatencyMS          float64 `json:"max_latency_ms,omitempty"`
	AverageLatencyMS      float64 `json:"average_latency_ms,omitempty"`
	JitterMS              float64 `json:"jitter_ms,omitempty"`
	DNSMS                 float64 `json:"dns_ms,omitempty"`
	ConnectMS             float64 `json:"connect_ms,omitempty"`
	TLSMS                 float64 `json:"tls_ms,omitempty"`
	TTFBMS                float64 `json:"ttfb_ms,omitempty"`
	HTTPStatusCode        int     `json:"http_status_code,omitempty"`
	HTTPStatusOKRatio     float64 `json:"http_status_ok_ratio,omitempty"`
	TCPRetransmissions    int     `json:"tcp_retransmissions,omitempty"`
	ResolvedAddressHash   string  `json:"resolved_address_hash,omitempty"`
	ResolvedAddressFamily string  `json:"resolved_address_family,omitempty"`
	DNSMode               string  `json:"dns_mode,omitempty"`
	ErrorCode             string  `json:"error_code,omitempty"`
}

type PingParams struct {
	TaskID  uint         `json:"ping_task_id"`
	Type    string       `json:"ping_type"`
	Target  string       `json:"ping_target"`
	Options ProbeOptions `json:"ping_options,omitempty"`
}

type TCPQualityTarget struct {
	Key          string `json:"key"`
	Address      string `json:"address"`
	Port         int    `json:"port"`
	Province     string `json:"province"`
	ProvinceCode string `json:"province_code"`
	ISP          string `json:"isp"`
	ISPCode      string `json:"isp_code"`
	IPVersion    int    `json:"ip_version"`
}

type TCPQualityParams struct {
	TaskID          uint               `json:"task_id"`
	RunID           string             `json:"run_id"`
	CatalogRevision string             `json:"catalog_revision"`
	Targets         []TCPQualityTarget `json:"targets"`
	StandardPackets int                `json:"standard_packets"`
	LargeEnabled    bool               `json:"large_enabled"`
	LargePackets    int                `json:"large_packets"`
	DelayMS         int                `json:"delay_ms"`
	TimeoutMS       int                `json:"timeout_ms"`
	MaxParallel     int                `json:"max_parallel"`
}

type TCPQualityTargetResult struct {
	TargetKey        string  `json:"target_key"`
	Mode             string  `json:"mode"`
	SamplesSent      int     `json:"samples_sent"`
	SamplesReceived  int     `json:"samples_received"`
	LossRatio        float64 `json:"loss_ratio"`
	MinLatencyMS     float64 `json:"min_latency_ms,omitempty"`
	MaxLatencyMS     float64 `json:"max_latency_ms,omitempty"`
	P50LatencyMS     float64 `json:"p50_latency_ms,omitempty"`
	P95LatencyMS     float64 `json:"p95_latency_ms,omitempty"`
	AverageLatencyMS float64 `json:"average_latency_ms,omitempty"`
	ErrorCode        string  `json:"error_code,omitempty"`
}

type TCPQualityResultParams struct {
	TaskID          uint                     `json:"task_id"`
	RunID           string                   `json:"run_id"`
	CatalogRevision string                   `json:"catalog_revision"`
	Results         []TCPQualityTargetResult `json:"results"`
	ErrorCode       string                   `json:"error_code,omitempty"`
	FinishedAt      time.Time                `json:"finished_at"`
}

func BuildTCPQualityResultPayload(params TCPQualityResultParams) interface{} {
	return Request{
		JSONRPC: Version,
		Method:  MethodAgentTCPQualityResult,
		Params:  params,
	}
}

func BuildPingResultPayload(taskID uint, pingType string, value int, details *ProbeResultDetails, finishedAt time.Time) interface{} {
	params := map[string]interface{}{
		"task_id":     taskID,
		"ping_type":   pingType,
		"value":       value,
		"finished_at": finishedAt.Format(time.RFC3339Nano),
	}
	if details != nil {
		params["details"] = details
	}
	return Request{
		JSONRPC: Version,
		Method:  MethodAgentPingResult,
		Params:  params,
	}
}

func BindParams(raw interface{}, target interface{}) error {
	b, err := json.Marshal(raw)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, target)
}

func BindResult(raw interface{}, target interface{}) error {
	return BindParams(raw, target)
}
