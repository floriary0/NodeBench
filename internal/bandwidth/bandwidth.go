package bandwidth

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

const (
	DefaultProbeSize = "512MB"
	DefaultHardLimit = int64(12 * 1024 * 1024 * 1024)
)

type Config struct {
	NodeURL      string
	ProbeSize    string
	HardLimit    int64
	TosutilPath  string
	ProbeTimeout time.Duration
}

type Outcome struct {
	Status     string
	Confidence string
	Message    string
	Warnings   []model.Warning
}

type node struct {
	Carrier string
	City    string
	Region  string
	IP      string
}

type probeResult struct {
	BPS     *float64
	Traffic int64
}

var ratePattern = regexp.MustCompile(`(?i)Average\s+(?:upload|download)\s+rate:\s*([0-9.]+)\s*([KMGT]?B/s)`)

func DefaultConfig(nodeURL string) Config {
	return Config{
		NodeURL: nodeURL, ProbeSize: DefaultProbeSize, HardLimit: DefaultHardLimit,
		TosutilPath: "tosutil", ProbeTimeout: 45 * time.Second,
	}
}

func Run(ctx context.Context, config Config, network map[string]any, routes []any) Outcome {
	config = normalize(config)
	tosutil, err := exec.LookPath(config.TosutilPath)
	if err != nil {
		return skipped("tosutil_missing", "未安装 tosutil，三网单线程带宽未测")
	}
	for _, command := range []string{"unshare", "mount"} {
		if _, err := exec.LookPath(command); err != nil {
			return skipped("mount_namespace_unavailable", "系统缺少挂载命名空间工具，三网带宽未测")
		}
	}
	iface := defaultInterface()
	if iface == "" {
		return skipped("network_interface_unavailable", "无法识别默认网络接口，三网带宽未测")
	}
	nodes, err := loadNodes(ctx, config.NodeURL)
	if err != nil {
		nodes = fallbackNodes()
	}

	rows := existingCarrierRows(network)
	totalTraffic := int64Value(network["traffic_bytes"])
	completed := 0
	budgetLimited := false
	for _, carrier := range []string{"telecom", "unicom", "mobile"} {
		target := nodes[carrier]
		row := rows[carrier]
		if row == nil {
			row = newCarrierRow(carrier, target.City, network, routes)
			rows[carrier] = row
		}
		enrichRoute(row, routes, carrier)
		for _, direction := range []string{"download", "upload"} {
			if totalTraffic >= config.HardLimit {
				budgetLimited = true
				row["budget_limited"] = true
				break
			}
			result := runProbe(ctx, config, tosutil, iface, target, direction)
			totalTraffic += result.Traffic
			if direction == "download" {
				row["download_bps"] = result.BPS
			} else {
				row["upload_bps"] = result.BPS
			}
			if result.BPS != nil {
				completed++
			}
		}
	}
	network["china_carriers"] = orderedRows(rows)
	network["traffic_bytes"] = totalTraffic
	network["traffic_hard_limit_bytes"] = config.HardLimit
	network["max_concurrency"] = 2

	status, confidence := "success", "high"
	if completed < 6 {
		status, confidence = "partial", "medium"
	}
	warnings := []model.Warning{}
	if budgetLimited {
		warnings = append(warnings, model.Warning{
			Code: "traffic_hard_limit_reached", Severity: "critical",
			Message: "带宽测试达到 12GB 硬上限，剩余方向已停止", Module: "bandwidth",
		})
	}
	return Outcome{
		Status: status, Confidence: confidence,
		Message:  fmt.Sprintf("三网单线程带宽完成 %d/6 个方向，流量约 %d MiB", completed, totalTraffic/(1024*1024)),
		Warnings: warnings,
	}
}

func enrichRoute(row map[string]any, routes []any, carrier string) {
	routeType, entry, asPath := carrierRoute(routes, carrier)
	if row["return_route"] == nil {
		row["return_route"] = routeType
	}
	if row["entry_city"] == nil {
		row["entry_city"] = entry
	}
	if current, ok := row["asn_path"].([]int64); !ok || len(current) == 0 {
		row["asn_path"] = asPath
	}
}

func runProbe(ctx context.Context, config Config, tosutil, iface string, target node, direction string) probeResult {
	tempDir, err := os.MkdirTemp("", "nodebench-bandwidth-*")
	if err != nil {
		return probeResult{}
	}
	defer os.RemoveAll(tempDir)
	hostsPath := filepath.Join(tempDir, "hosts")
	hosts, _ := os.ReadFile("/etc/hosts")
	mapping := fmt.Sprintf("\n%s tos-%s.volces.com tos7-public.%s.tos.volces.com\n",
		target.IP, target.Region, target.Region)
	if err := os.WriteFile(hostsPath, append(hosts, []byte(mapping)...), 0o600); err != nil {
		return probeResult{}
	}

	before := interfaceBytes(iface)
	probeCtx, cancel := context.WithTimeout(ctx, config.ProbeTimeout)
	defer cancel()
	script := `mount --bind "$1" /etc/hosts && shift && exec "$@"`
	args := []string{
		"--mount", "--propagation", "private", "--", "/bin/sh", "-c", script,
		"nodebench-probe", hostsPath, tosutil, "probe",
		"-tr", target.Region, "-pt", direction, "-nt", "public",
		"-ps", config.ProbeSize, "-timeout", "30",
	}
	output, _ := exec.CommandContext(probeCtx, "unshare", args...).CombinedOutput()
	after := interfaceBytes(iface)
	traffic := after - before
	if traffic < 0 {
		traffic = 0
	}
	bps := parseRate(output)
	return probeResult{BPS: bps, Traffic: traffic}
}

func loadNodes(ctx context.Context, rawURL string) (map[string]node, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	query.Set("format", "tsv")
	query.Set("scope", "tos")
	parsed.RawQuery = query.Encode()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	client := &http.Client{Timeout: 20 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("node catalog HTTP %d", response.StatusCode)
	}
	result := map[string]node{}
	scanner := bufio.NewScanner(io.LimitReader(response.Body, 512*1024))
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 8 || fields[0] == "type" || fields[1] != "4" {
			continue
		}
		carrier := normalizeCarrier(fields[3])
		ip := net.ParseIP(strings.TrimSpace(fields[5]))
		if carrier == "" || ip == nil || ip.To4() == nil {
			continue
		}
		region := "cn-beijing"
		switch {
		case strings.Contains(fields[7], "cn-shanghai"):
			region = "cn-shanghai"
		case strings.Contains(fields[7], "cn-guangzhou"):
			region = "cn-guangzhou"
		}
		if _, exists := result[carrier]; !exists {
			result[carrier] = node{Carrier: carrier, City: fields[2], Region: region, IP: ip.String()}
		}
	}
	if len(result) < 3 {
		return nil, fmt.Errorf("三网 TOS 节点不完整")
	}
	return result, nil
}

func fallbackNodes() map[string]node {
	return map[string]node{
		"telecom": {Carrier: "telecom", City: "北京", Region: "cn-beijing", IP: "42.81.80.86"},
		"unicom":  {Carrier: "unicom", City: "北京", Region: "cn-beijing", IP: "221.194.175.109"},
		"mobile":  {Carrier: "mobile", City: "北京", Region: "cn-beijing", IP: "120.255.0.180"},
	}
}

func newCarrierRow(carrier, city string, network map[string]any, routes []any) map[string]any {
	latency, loss := carrierQuality(network, carrier)
	routeType, entry, asPath := carrierRoute(routes, carrier)
	return map[string]any{
		"carrier": carrier, "representative_city": city,
		"latency_ms": latency, "jitter_ms": nil, "loss_ratio": loss,
		"download_bps": nil, "upload_bps": nil, "outbound_route": nil,
		"return_route": routeType, "entry_city": entry, "asn_path": asPath,
		"budget_limited": false,
	}
}

func carrierQuality(network map[string]any, carrier string) (any, any) {
	rows, _ := network["province_tcp"].([]any)
	latencies, losses := []float64{}, []float64{}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok || row["carrier"] != carrier {
			continue
		}
		if value, ok := floatValue(row["latency_ms"]); ok {
			latencies = append(latencies, value)
		}
		if value, ok := floatValue(row["retransmission_ratio"]); ok {
			losses = append(losses, value)
		}
	}
	return nullableAverage(latencies), nullableAverage(losses)
}

func carrierRoute(routes []any, carrier string) (any, any, []int64) {
	counts := map[string]int{}
	candidates := map[string]map[string]any{}
	for _, raw := range routes {
		route, ok := raw.(map[string]any)
		if !ok || route["carrier"] != carrier {
			continue
		}
		routeType, _ := route["route_type"].(string)
		if routeType == "" || routeType == "Hidden" {
			continue
		}
		counts[routeType]++
		if _, exists := candidates[routeType]; !exists {
			candidates[routeType] = route
		}
	}
	selected := ""
	for routeType, count := range counts {
		if selected == "" || count > counts[selected] ||
			(count == counts[selected] && routeQuality(routeType) > routeQuality(selected)) {
			selected = routeType
		}
	}
	if selected == "" {
		return nil, nil, []int64{}
	}
	route := candidates[selected]
	asPath := []int64{}
	if values, ok := route["as_path"].([]int64); ok {
		asPath = values
	} else if values, ok := route["as_path"].([]any); ok {
		for _, rawASN := range values {
			if value, ok := floatValue(rawASN); ok {
				asPath = append(asPath, int64(value))
			}
		}
	}
	return selected, route["entry_city"], asPath
}

func routeQuality(value string) int {
	upper := strings.NewReplacer(" ", "", "-", "", "_", "").Replace(strings.ToUpper(value))
	switch {
	case strings.Contains(upper, "CN2GIA"), strings.Contains(upper, "CTGGIA"),
		strings.Contains(upper, "9929"), strings.Contains(upper, "CMIN2"):
		return 5
	case strings.Contains(upper, "CN2GT"), strings.Contains(upper, "10099"):
		return 4
	case strings.Contains(upper, "CMI"), strings.Contains(upper, "4837"):
		return 3
	case strings.Contains(upper, "163"), strings.Contains(upper, "9808"):
		return 2
	default:
		return 1
	}
}

func existingCarrierRows(network map[string]any) map[string]map[string]any {
	result := map[string]map[string]any{}
	rows, _ := network["china_carriers"].([]any)
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		carrier, _ := row["carrier"].(string)
		if ok && carrier != "" {
			result[carrier] = row
		}
	}
	return result
}

func orderedRows(rows map[string]map[string]any) []any {
	result := []any{}
	for _, carrier := range []string{"telecom", "unicom", "mobile"} {
		if row := rows[carrier]; row != nil {
			result = append(result, row)
		}
	}
	return result
}

func parseRate(output []byte) *float64 {
	match := ratePattern.FindSubmatch(output)
	if len(match) != 3 {
		return nil
	}
	value, err := strconv.ParseFloat(string(match[1]), 64)
	if err != nil {
		return nil
	}
	multiplier := map[string]float64{
		"B/S": 8, "KB/S": 8e3, "MB/S": 8e6, "GB/S": 8e9, "TB/S": 8e12,
	}[strings.ToUpper(string(match[2]))]
	result := value * multiplier
	return &result
}

func normalize(config Config) Config {
	if config.ProbeSize == "" {
		config.ProbeSize = DefaultProbeSize
	}
	if config.HardLimit <= 0 {
		config.HardLimit = DefaultHardLimit
	}
	if config.TosutilPath == "" {
		config.TosutilPath = "tosutil"
	}
	if config.ProbeTimeout <= 0 {
		config.ProbeTimeout = 45 * time.Second
	}
	return config
}

func normalizeCarrier(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "电信", "ct", "chinatelecom":
		return "telecom"
	case "联通", "cu", "chinaunicom":
		return "unicom"
	case "移动", "cm", "chinamobile":
		return "mobile"
	default:
		return ""
	}
}

func defaultInterface() string {
	file, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 && fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func interfaceBytes(iface string) int64 {
	read := func(name string) int64 {
		data, err := os.ReadFile(filepath.Join("/sys/class/net", iface, "statistics", name))
		if err != nil {
			return 0
		}
		value, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
		return value
	}
	return read("rx_bytes") + read("tx_bytes")
}

func nullableAverage(values []float64) any {
	if len(values) == 0 {
		return nil
	}
	total := 0.0
	for _, value := range values {
		total += value
	}
	return math.Round(total/float64(len(values))*100) / 100
}

func floatValue(value any) (float64, bool) {
	switch number := value.(type) {
	case int:
		return float64(number), true
	case int64:
		return float64(number), true
	case float64:
		return number, true
	default:
		return 0, false
	}
}

func int64Value(value any) int64 {
	number, _ := floatValue(value)
	return int64(number)
}

func skipped(code, message string) Outcome {
	return Outcome{
		Status: "skipped", Confidence: "low", Message: message,
		Warnings: []model.Warning{{Code: code, Severity: "warning", Message: message, Module: "bandwidth"}},
	}
}
