package routes

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nodebench/nodebench/internal/model"
	"github.com/nodebench/nodebench/internal/privacy"
	"github.com/nodebench/nodebench/internal/tcpquality"
)

type Config struct {
	NodeURL     string
	Concurrency int
}

type Outcome struct {
	Status     string
	Confidence string
	Message    string
	Warnings   []model.Warning
}

type traceResult struct {
	Target tcpquality.Target
	Hops   []string
	Error  string
}

type commandRunner interface {
	Exists(string) bool
	Run(context.Context, string, ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type asnLookup interface {
	Lookup(context.Context, []string) (map[string]int64, error)
}

type cymruLookup struct{}

func (cymruLookup) Lookup(ctx context.Context, ips []string) (map[string]int64, error) {
	dialer := net.Dialer{Timeout: 8 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", "whois.cymru.com:43")
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(35 * time.Second))
	var request strings.Builder
	request.WriteString("begin\nverbose\n")
	for _, ip := range uniqueStrings(ips) {
		request.WriteString(ip)
		request.WriteByte('\n')
	}
	request.WriteString("end\n")
	if _, err := io.WriteString(connection, request.String()); err != nil {
		return nil, err
	}
	return parseCymru(connection)
}

func Run(ctx context.Context, config Config, routeOutput *[]any) Outcome {
	return run(ctx, config, execRunner{}, cymruLookup{}, routeOutput)
}

func run(ctx context.Context, config Config, commands commandRunner, lookup asnLookup, routeOutput *[]any) Outcome {
	config = normalizeConfig(config)
	if !commands.Exists("traceroute") {
		return Outcome{
			Status: "skipped", Confidence: "low", Message: "未安装 traceroute，回程线路未测",
			Warnings: []model.Warning{warning("traceroute_missing", "未安装 traceroute，回程线路识别已跳过")},
		}
	}
	targets, err := tcpquality.LoadChinaTargets(ctx, config.NodeURL)
	if err != nil {
		return Outcome{
			Status: "failed", Confidence: "low", Message: "三网线路节点获取失败",
			Warnings: []model.Warning{warning("route_nodes_unavailable", err.Error())},
		}
	}
	traces := traceAll(ctx, commands, targets, config.Concurrency)
	var allIPs []string
	for _, trace := range traces {
		allIPs = append(allIPs, trace.Hops...)
	}
	asnByIP, lookupErr := lookup.Lookup(ctx, allIPs)
	if asnByIP == nil {
		asnByIP = map[string]int64{}
	}
	routes := make([]any, 0, len(traces))
	failed := 0
	for _, trace := range traces {
		if len(trace.Hops) == 0 {
			failed++
			continue
		}
		asPath := make([]int64, 0, len(trace.Hops))
		masked := make([]string, 0, len(trace.Hops))
		for _, ip := range trace.Hops {
			asn := asnByIP[ip]
			if asn == 0 {
				asn = inferASN(ip)
			}
			if asn > 0 && (len(asPath) == 0 || asPath[len(asPath)-1] != asn) {
				asPath = append(asPath, asn)
			}
			if value, maskErr := maskHop(ip); maskErr == nil {
				masked = append(masked, value)
			}
		}
		label := classify(trace.Hops, asnByIP, trace.Target.Carrier)
		routes = append(routes, map[string]any{
			"carrier": trace.Target.Carrier, "direction": "return",
			"region": trace.Target.Province, "target_city": trace.Target.Province,
			"route_type": label, "entry_city": nil, "hop_count": len(trace.Hops),
			"direct": nil, "detour": nil, "as_path": asPath,
			"masked_hops": masked,
			"summary": fmt.Sprintf("%s%s回程 · %s · %d 跳",
				trace.Target.Province, carrierName(trace.Target.Carrier), label, len(trace.Hops)),
		})
	}
	*routeOutput = routes
	status, confidence := "success", "high"
	var warnings []model.Warning
	if lookupErr != nil {
		status, confidence = "partial", "medium"
		warnings = append(warnings, warning("cymru_unavailable", "Team Cymru ASN 查询失败，已使用 IP 段规则降级分类"))
	}
	if failed > 0 {
		status, confidence = "partial", "medium"
		warnings = append(warnings, warning("route_trace_partial", fmt.Sprintf("%d/%d 个线路目标没有有效 hop", failed, len(traces))))
	}
	return Outcome{
		Status: status, Confidence: confidence,
		Message:  fmt.Sprintf("完成 %d/%d 个三网 TCP 回程线路", len(routes), len(traces)),
		Warnings: warnings,
	}
}

func normalizeConfig(config Config) Config {
	if config.NodeURL == "" {
		config.NodeURL = tcpquality.DefaultNodeURL
	}
	if config.Concurrency < 1 {
		config.Concurrency = 16
	}
	if config.Concurrency > 16 {
		config.Concurrency = 16
	}
	return config
}

func traceAll(ctx context.Context, commands commandRunner, targets []tcpquality.Target, concurrency int) []traceResult {
	type job struct {
		index  int
		target tcpquality.Target
	}
	jobs := make(chan job)
	results := make([]traceResult, len(targets))
	var wait sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for item := range jobs {
				results[item.index] = traceOne(ctx, commands, item.target)
			}
		}()
	}
	for index, target := range targets {
		jobs <- job{index: index, target: target}
	}
	close(jobs)
	wait.Wait()
	return results
}

func traceOne(ctx context.Context, commands commandRunner, target tcpquality.Target) traceResult {
	traceCtx, cancel := context.WithTimeout(ctx, 70*time.Second)
	defer cancel()
	output, err := commands.Run(traceCtx, "traceroute",
		"-n", "-4", "-T", "-p", strconv.Itoa(target.Port),
		"-q", "3", "-w", "2", "-m", "30", target.IP, "44")
	hops := parseTraceroute(string(output))
	result := traceResult{Target: target, Hops: hops}
	if err != nil && len(hops) == 0 {
		result.Error = err.Error()
	}
	return result
}

var ipv4Pattern = regexp.MustCompile(`(?:^|[^0-9])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:$|[^0-9])`)

func parseTraceroute(output string) []string {
	var hops []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			continue
		}
		match := ipv4Pattern.FindStringSubmatch(" " + line + " ")
		if len(match) != 2 || net.ParseIP(match[1]) == nil {
			continue
		}
		if len(hops) == 0 || hops[len(hops)-1] != match[1] {
			hops = append(hops, match[1])
		}
	}
	return hops
}

func parseCymru(reader io.Reader) (map[string]int64, error) {
	result := map[string]int64{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "|")
		if len(fields) < 2 {
			continue
		}
		asn, err := strconv.ParseInt(strings.TrimSpace(fields[0]), 10, 64)
		ip := strings.TrimSpace(fields[1])
		if err == nil && net.ParseIP(ip) != nil {
			result[ip] = asn
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return result, errors.New("Team Cymru 未返回 ASN")
	}
	return result, nil
}

func classify(hops []string, asnByIP map[string]int64, carrier string) string {
	asns := make([]int64, len(hops))
	firstCN2 := -1
	hasCTG := false
	for index, ip := range hops {
		asns[index] = asnByIP[ip]
		if asns[index] == 0 {
			asns[index] = inferASN(ip)
		}
		if asns[index] == 4809 || strings.HasPrefix(ip, "59.43.") {
			if firstCN2 == -1 {
				firstCN2 = index
			}
		}
		if asns[index] == 23764 || isCTG(ip) {
			hasCTG = true
		}
	}
	if firstCN2 >= 0 {
		for index := firstCN2 + 1; index < len(hops); index++ {
			if asns[index] == 4134 || is163(hops[index]) {
				return "CN2GT"
			}
		}
		if hasCTG {
			return "CTGGIA"
		}
		return "CN2GIA"
	}
	first10099 := indexASN(asns, 10099)
	if first10099 >= 0 {
		if indexAfter(asns, 9929, first10099) >= 0 {
			return "10099->9929"
		}
		if indexAfter(asns, 4837, first10099) >= 0 || indexAfter(asns, 4808, first10099) >= 0 {
			return "10099->4837"
		}
		return "10099"
	}
	for _, candidate := range []struct {
		asn   int64
		label string
	}{
		{58807, "CMIN2"}, {9929, "9929"}, {4837, "4837"}, {4808, "4837"},
		{58453, "CMI"}, {9808, "CMI"}, {23911, "CERNET2"},
		{23910, "CERNET2"}, {4538, "CERNET"}, {7497, "CSTNET"},
	} {
		if indexASN(asns, candidate.asn) >= 0 {
			return candidate.label
		}
	}
	for _, asn := range asns {
		if asn >= 56040 && asn <= 56048 {
			return "CMI"
		}
	}
	for index, ip := range hops {
		switch {
		case asns[index] == 4134 || asns[index] == 4847 || is163(ip):
			return "163"
		case carrier == "mobile" && (isMobile(ip) || asns[index] == 24547 || asns[index] == 132510):
			return "CMI"
		case carrier == "unicom" && isUnicom(ip):
			return "4837"
		}
	}
	return "Hidden"
}

// EnrichProvinceRows joins route classification back into the corresponding
// TCP-quality row using only sanitized report fields.
func EnrichProvinceRows(network map[string]any, routeOutput []any) {
	rows, ok := network["province_tcp"].([]any)
	if !ok {
		return
	}
	routeTypes := map[string]any{}
	for _, raw := range routeOutput {
		route, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		carrier, _ := route["carrier"].(string)
		region, _ := route["target_city"].(string)
		if region == "" {
			region, _ = route["region"].(string)
		}
		if carrier != "" && region != "" {
			routeTypes[carrier+"\x00"+region] = route["route_type"]
		}
	}
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		carrier, _ := row["carrier"].(string)
		province, _ := row["province"].(string)
		if routeType, exists := routeTypes[carrier+"\x00"+province]; exists {
			row["route"] = routeType
		}
	}
}

func inferASN(ip string) int64 {
	switch {
	case strings.HasPrefix(ip, "59.43."):
		return 4809
	case isCTG(ip):
		return 23764
	case is163(ip):
		return 4134
	case isUnicom(ip):
		return 4837
	case strings.HasPrefix(ip, "223.120."), strings.HasPrefix(ip, "223.119."):
		return 58453
	case isMobile(ip):
		return 9808
	case is10099(ip):
		return 10099
	case strings.HasPrefix(ip, "210.14."), strings.HasPrefix(ip, "210.51."),
		strings.HasPrefix(ip, "210.78."), strings.HasPrefix(ip, "218.105."):
		return 9929
	default:
		return 0
	}
}

func isCTG(ip string) bool {
	return hasPrefix(ip, "203.22.182.", "203.22.178.", "203.22.179.", "203.128.224.", "69.194.")
}

func is163(ip string) bool {
	return hasPrefix(ip, "202.97.", "202.96.", "219.141.", "219.142.", "106.37.")
}

func isUnicom(ip string) bool {
	return hasPrefix(ip, "219.158.", "210.14.", "210.51.", "210.78.", "218.105.")
}

func isMobile(ip string) bool {
	return hasPrefix(ip, "221.183.", "111.24.", "111.13.")
}

func is10099(ip string) bool {
	return hasPrefix(ip, "103.214.", "103.228.68.", "103.239.176.", "118.26.151.", "202.77.23.", "203.160.75.")
}

func hasPrefix(value string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func indexASN(values []int64, target int64) int {
	return indexAfter(values, target, -1)
}

func indexAfter(values []int64, target int64, after int) int {
	for index := after + 1; index < len(values); index++ {
		if values[index] == target {
			return index
		}
	}
	return -1
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func carrierName(value string) string {
	switch value {
	case "telecom":
		return "电信"
	case "unicom":
		return "联通"
	case "mobile":
		return "移动"
	default:
		return value
	}
}

func maskHop(ip string) (string, error) {
	return privacy.MaskIP(ip)
}

func warning(code, message string) model.Warning {
	return model.Warning{Code: code, Severity: "warning", Message: message, Module: "routes"}
}
