package tcpquality

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nodebench/nodebench/internal/model"
)

const DefaultNodeURL = "https://tcpquality.ibsgss.uk/getNodes?format=tsv&scope=cdn"

type Config struct {
	NodeURL              string
	ChinaPackets         int
	InternationalPackets int
	Concurrency          int
}

type Outcome struct {
	Status     string
	Confidence string
	Message    string
	Warnings   []model.Warning
}

type Target struct {
	Name     string
	Category string
	Province string
	Carrier  string
	Host     string
	IP       string
	Port     int
	Packets  int
	China    bool
}

type Result struct {
	Target       Target
	Sent         int
	Received     int
	LossRatio    float64
	AverageRTTMS *float64
	JitterMS     *float64
	TrafficBytes int64
	Error        string
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

type resolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

type netResolver struct{}

func (netResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, network, host)
}

func DefaultConfig() Config {
	return Config{
		NodeURL: DefaultNodeURL, ChinaPackets: 30,
		InternationalPackets: 15, Concurrency: 16,
	}
}

func Run(ctx context.Context, config Config, network map[string]any) Outcome {
	return run(ctx, config, execRunner{}, netResolver{}, http.DefaultClient, network)
}

func LoadChinaTargets(ctx context.Context, nodeURL string) ([]Target, error) {
	config := normalizeConfig(Config{NodeURL: nodeURL, ChinaPackets: 1, InternationalPackets: 1, Concurrency: 1})
	return loadChinaTargets(ctx, http.DefaultClient, config)
}

func run(ctx context.Context, config Config, commands commandRunner, dns resolver, client *http.Client, network map[string]any) Outcome {
	config = normalizeConfig(config)
	if !commands.Exists("nping") {
		return Outcome{
			Status: "skipped", Confidence: "low", Message: "未安装 nping，TCP 质量未测",
			Warnings: []model.Warning{warning("nping_missing", "未安装 nping，TCP SYN 质量探测已跳过")},
		}
	}

	international, resolveWarnings := buildInternationalTargets(ctx, dns, config.InternationalPackets)
	china, nodeErr := loadChinaTargets(ctx, client, config)
	targets := append(china, international...)
	if len(targets) == 0 {
		message := "没有可执行的 TCP 质量目标"
		return Outcome{
			Status: "failed", Confidence: "low", Message: message,
			Warnings: []model.Warning{warning("tcp_targets_empty", message)},
		}
	}

	results := probeAll(ctx, commands, targets, config.Concurrency)
	applyResults(network, results, config.Concurrency)
	warnings := append([]model.Warning{}, resolveWarnings...)
	status, confidence := "success", "high"
	message := fmt.Sprintf("完成 %d 个 TCP SYN 目标", len(results))
	if nodeErr != nil {
		status, confidence = "partial", "medium"
		warnings = append(warnings, warning("china_nodes_unavailable", "三网节点目录获取失败："+nodeErr.Error()))
		message = fmt.Sprintf("完成 %d 个国际 TCP SYN 目标，三网节点未执行", len(results))
	}
	return Outcome{Status: status, Confidence: confidence, Message: message, Warnings: warnings}
}

func normalizeConfig(config Config) Config {
	if config.NodeURL == "" {
		config.NodeURL = DefaultNodeURL
	}
	if config.ChinaPackets < 1 || config.ChinaPackets > 600 {
		config.ChinaPackets = 30
	}
	if config.InternationalPackets < 1 || config.InternationalPackets > 600 {
		config.InternationalPackets = 15
	}
	if config.Concurrency < 1 {
		config.Concurrency = 16
	}
	if config.Concurrency > 16 {
		config.Concurrency = 16
	}
	return config
}

func loadChinaTargets(ctx context.Context, client *http.Client, config Config) ([]Target, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.NodeURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "NodeBench/"+model.ClientVersion)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("节点目录 HTTP %d", response.StatusCode)
	}
	return parseNodeTSV(io.LimitReader(response.Body, 512*1024), config.ChinaPackets)
}

func parseNodeTSV(reader io.Reader, packets int) ([]Target, error) {
	var targets []Target
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "\t")
		if len(fields) < 7 || fields[0] == "type" {
			continue
		}
		if fields[0] != "cdn" || fields[1] != "4" {
			continue
		}
		ip := net.ParseIP(strings.TrimSpace(fields[5]))
		if ip == nil || ip.To4() == nil || !publicIPv4(ip.To4()) {
			continue
		}
		port, err := strconv.Atoi(fields[6])
		if err != nil || port < 1 || port > 65535 {
			port = 80
		}
		carrier := normalizeCarrier(fields[3])
		if carrier == "" {
			continue
		}
		targets = append(targets, Target{
			Name: fields[2] + " " + fields[3], Category: "china",
			Province: fields[2], Carrier: carrier, Host: fields[4],
			IP: ip.String(), Port: port, Packets: packets, China: true,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errors.New("节点目录没有有效 IPv4 节点")
	}
	return targets, nil
}

func buildInternationalTargets(ctx context.Context, dns resolver, packets int) ([]Target, []model.Warning) {
	specs := append(siteTargets(), cdnTargets()...)
	targets := make([]Target, 0, len(specs))
	var warnings []model.Warning
	for _, spec := range specs {
		lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := dns.LookupIP(lookupCtx, "ip4", spec.Host)
		cancel()
		if err != nil {
			warnings = append(warnings, warning("dns_resolve_failed", "无法解析 "+spec.Host))
			continue
		}
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && publicIPv4(ip4) {
				spec.IP = ip4.String()
				spec.Port = 443
				spec.Packets = packets
				targets = append(targets, spec)
				break
			}
		}
	}
	return targets, warnings
}

func probeAll(ctx context.Context, commands commandRunner, targets []Target, concurrency int) []Result {
	type job struct {
		index  int
		target Target
	}
	jobs := make(chan job)
	results := make([]Result, len(targets))
	var wait sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for item := range jobs {
				results[item.index] = probeTarget(ctx, commands, item.target)
			}
		}()
	}
	for index, target := range targets {
		select {
		case jobs <- job{index: index, target: target}:
		case <-ctx.Done():
			close(jobs)
			wait.Wait()
			return results[:index]
		}
	}
	close(jobs)
	wait.Wait()
	return results
}

func probeTarget(ctx context.Context, commands commandRunner, target Target) Result {
	result := Result{Target: target, Sent: target.Packets}
	rtts := make([]float64, 0, target.Packets)
	packetSizes := []int{40, 80, 160, 320, 640, 1200}
	for index := 0; index < target.Packets; index++ {
		if ctx.Err() != nil {
			result.Sent = index
			result.Error = ctx.Err().Error()
			break
		}
		packetSize := packetSizes[randomInt(len(packetSizes))]
		sourcePort := 20000 + randomInt(40000)
		sequence := randomInt(math.MaxInt32 - 1)
		args := []string{
			"--tcp", "-p", strconv.Itoa(target.Port), "--flags", "syn",
			"-g", strconv.Itoa(sourcePort), "--seq", strconv.Itoa(sequence),
		}
		if payload := packetSize - 40; payload > 0 {
			args = append(args, "--data-length", strconv.Itoa(payload))
		}
		args = append(args, "-c", "1", target.IP)
		packetCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		output, _ := commands.Run(packetCtx, "nping", args...)
		cancel()
		result.TrafficBytes += int64(packetSize)
		if rtt, err := parseMatchingRTT(string(output)); err == nil {
			result.Received++
			rtts = append(rtts, rtt)
			result.TrafficBytes += 40
		}
	}
	if result.Sent > 0 {
		result.LossRatio = float64(result.Sent-result.Received) / float64(result.Sent)
	}
	if len(rtts) > 0 {
		average := mean(rtts)
		result.AverageRTTMS = &average
		jitter := meanAbsoluteDelta(rtts)
		result.JitterMS = &jitter
	} else {
		result.Error = "unreachable"
	}
	return result
}

func parseMatchingRTT(output string) (float64, error) {
	var sent *endpointValue
	minimum := math.MaxFloat64
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		kind := ""
		switch {
		case strings.HasPrefix(line, "SENT ") && strings.Contains(line, " TCP "):
			kind = "sent"
		case strings.HasPrefix(line, "RCVD ") && strings.Contains(line, " TCP "):
			kind = "received"
		default:
			continue
		}
		current, destination, err := parseNpingLine(line)
		if err != nil {
			continue
		}
		if kind == "sent" && sent == nil {
			value := current
			value.port = current.port + "|" + destination.ip + "|" + destination.port
			sent = &value
			continue
		}
		if kind == "received" && sent != nil {
			parts := strings.Split(sent.port, "|")
			if len(parts) != 3 {
				continue
			}
			if current.ip == parts[1] && current.port == parts[2] &&
				destination.ip == sent.ip && destination.port == parts[0] {
				rtt := (current.time - sent.time) * 1000
				if rtt >= 0 && rtt < minimum {
					minimum = rtt
				}
			}
		}
	}
	if minimum == math.MaxFloat64 {
		return 0, errors.New("未找到匹配的 SYN 响应")
	}
	return minimum, nil
}

func parseNpingLine(line string) (source endpointValue, destination endpointValue, err error) {
	open := strings.Index(line, "(")
	close := strings.Index(line, "s)")
	tcp := strings.Index(line, " TCP ")
	if open < 0 || close <= open || tcp < 0 {
		return source, destination, errors.New("格式无效")
	}
	timestamp, err := strconv.ParseFloat(line[open+1:close], 64)
	if err != nil {
		return source, destination, err
	}
	body := line[tcp+5:]
	parts := strings.SplitN(body, " > ", 2)
	if len(parts) != 2 {
		return source, destination, errors.New("端点无效")
	}
	left := strings.Fields(parts[0])
	right := strings.Fields(parts[1])
	if len(left) == 0 || len(right) == 0 {
		return source, destination, errors.New("端点缺失")
	}
	source, err = splitEndpoint(left[0])
	if err != nil {
		return source, destination, err
	}
	destination, err = splitEndpoint(right[0])
	if err != nil {
		return source, destination, err
	}
	source.time, destination.time = timestamp, timestamp
	return source, destination, nil
}

type endpointValue struct {
	ip   string
	port string
	time float64
}

func splitEndpoint(value string) (endpointValue, error) {
	index := strings.LastIndex(value, ":")
	if index <= 0 || index == len(value)-1 {
		return endpointValue{}, errors.New("端点格式无效")
	}
	return endpointValue{ip: strings.ToLower(value[:index]), port: value[index+1:]}, nil
}

func applyResults(network map[string]any, results []Result, concurrency int) {
	var provinces, global, cdn []any
	var traffic int64
	zero, light, severe := 0, 0, 0
	carrierResults := map[string][]Result{}
	for _, result := range results {
		traffic += result.TrafficBytes
		if result.Target.China {
			provinces = append(provinces, map[string]any{
				"province": result.Target.Province, "carrier": result.Target.Carrier,
				"route": nil, "latency_ms": result.AverageRTTMS,
				"retransmission_ratio": ratioOrNil(result),
			})
			carrierResults[result.Target.Carrier] = append(carrierResults[result.Target.Carrier], result)
			switch {
			case result.LossRatio == 0:
				zero++
			case result.LossRatio <= 0.2:
				light++
			default:
				severe++
			}
			continue
		}
		target := map[string]any{
			"name": result.Target.Name, "category": result.Target.Category,
			"reachable": result.Received > 0, "latency_ms": result.AverageRTTMS,
			"retransmission_ratio": ratioOrNil(result),
		}
		if result.Target.Category == "cdn" {
			cdn = append(cdn, target)
		} else {
			global = append(global, target)
		}
	}
	network["province_tcp"] = provinces
	network["china_carriers"] = aggregateCarriers(carrierResults)
	network["tcp_quality_summary"] = map[string]any{
		"zero_retransmission_count":   zero,
		"light_retransmission_count":  light,
		"severe_retransmission_count": severe,
	}
	network["global_targets"] = global
	network["cdn_targets"] = cdn
	network["global_target_summary"] = summarizeTargets(results, "site")
	network["cdn_target_summary"] = summarizeTargets(results, "cdn")
	network["traffic_bytes"] = traffic
	network["max_concurrency"] = concurrency
}

func aggregateCarriers(grouped map[string][]Result) []any {
	order := []string{"telecom", "unicom", "mobile"}
	output := make([]any, 0, len(order))
	for _, carrier := range order {
		results := grouped[carrier]
		if len(results) == 0 {
			continue
		}
		var latencies, jitters []float64
		loss := 0.0
		for _, result := range results {
			loss += result.LossRatio
			if result.AverageRTTMS != nil {
				latencies = append(latencies, *result.AverageRTTMS)
			}
			if result.JitterMS != nil {
				jitters = append(jitters, *result.JitterMS)
			}
		}
		output = append(output, map[string]any{
			"carrier": carrier, "representative_city": "全国节点",
			"latency_ms": medianOrNil(latencies), "jitter_ms": meanOrNil(jitters),
			"loss_ratio":   loss / float64(len(results)),
			"download_bps": nil, "upload_bps": nil,
			"outbound_route": nil, "return_route": nil, "entry_city": nil,
			"asn_path": []int64{}, "budget_limited": false,
		})
	}
	return output
}

func summarizeTargets(results []Result, category string) map[string]any {
	tested, reachable := 0, 0
	var latencies []float64
	for _, result := range results {
		if result.Target.China || result.Target.Category != category {
			continue
		}
		tested++
		if result.Received > 0 {
			reachable++
			latencies = append(latencies, *result.AverageRTTMS)
		}
	}
	return map[string]any{
		"tested": tested, "reachable": reachable,
		"median_latency_ms": medianOrNil(latencies),
	}
}

func ratioOrNil(result Result) any {
	if result.Sent == 0 {
		return nil
	}
	return result.LossRatio
}

func publicIPv4(ip net.IP) bool {
	if len(ip) != net.IPv4len {
		return false
	}
	return !(ip[0] == 0 || ip[0] == 10 || ip[0] == 127 || ip[0] >= 224 ||
		(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) ||
		(ip[0] == 169 && ip[1] == 254) ||
		(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
		(ip[0] == 192 && ip[1] == 168) ||
		(ip[0] == 192 && ip[1] == 0 && (ip[2] == 0 || ip[2] == 2)) ||
		(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) ||
		(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) ||
		(ip[0] == 203 && ip[1] == 0 && ip[2] == 113))
}

func normalizeCarrier(value string) string {
	switch strings.TrimSpace(value) {
	case "电信":
		return "telecom"
	case "联通":
		return "unicom"
	case "移动":
		return "mobile"
	default:
		return ""
	}
}

func randomInt(maximum int) int {
	if maximum <= 1 {
		return 0
	}
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return int(time.Now().UnixNano() % int64(maximum))
	}
	return int(binary.BigEndian.Uint64(bytes[:]) % uint64(maximum))
}

func mean(values []float64) float64 {
	total := 0.0
	for _, value := range values {
		total += value
	}
	return total / float64(len(values))
}

func meanAbsoluteDelta(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	total := 0.0
	for index := 1; index < len(values); index++ {
		total += math.Abs(values[index] - values[index-1])
	}
	return total / float64(len(values)-1)
}

func meanOrNil(values []float64) any {
	if len(values) == 0 {
		return nil
	}
	return mean(values)
}

func medianOrNil(values []float64) any {
	if len(values) == 0 {
		return nil
	}
	copied := append([]float64{}, values...)
	sort.Float64s(copied)
	middle := len(copied) / 2
	if len(copied)%2 == 0 {
		return (copied[middle-1] + copied[middle]) / 2
	}
	return copied[middle]
}

func warning(code, message string) model.Warning {
	return model.Warning{Code: code, Severity: "warning", Message: message, Module: "tcp_quality"}
}

func siteTargets() []Target {
	return []Target{
		{Name: "Adobe Assets", Category: "site", Host: "assets.adobe.com"},
		{Name: "Amazon", Category: "site", Host: "www.amazon.com"},
		{Name: "Apple iCloud", Category: "site", Host: "www.icloud.com"},
		{Name: "AWS STS", Category: "site", Host: "sts.amazonaws.com"},
		{Name: "ChatGPT", Category: "site", Host: "chatgpt.com"},
		{Name: "Claude", Category: "site", Host: "claude.ai"},
		{Name: "Cloudflare Dashboard", Category: "site", Host: "dash.cloudflare.com"},
		{Name: "Discord Gateway", Category: "site", Host: "gateway.discord.gg"},
		{Name: "Dropbox API", Category: "site", Host: "api.dropboxapi.com"},
		{Name: "Facebook", Category: "site", Host: "www.facebook.com"},
		{Name: "GitHub API", Category: "site", Host: "api.github.com"},
		{Name: "GitLab", Category: "site", Host: "gitlab.com"},
		{Name: "Gmail", Category: "site", Host: "mail.google.com"},
		{Name: "Google Search", Category: "site", Host: "www.google.com"},
		{Name: "Google Static", Category: "site", Host: "www.gstatic.com"},
		{Name: "Instagram", Category: "site", Host: "www.instagram.com"},
		{Name: "Microsoft Login", Category: "site", Host: "login.microsoftonline.com"},
		{Name: "Netflix API", Category: "site", Host: "api-global.netflix.com"},
		{Name: "NodeSeek", Category: "site", Host: "www.nodeseek.com"},
		{Name: "Notion API", Category: "site", Host: "api.notion.com"},
		{Name: "OpenAI API", Category: "site", Host: "api.openai.com"},
		{Name: "PayPal API", Category: "site", Host: "api-m.paypal.com"},
		{Name: "Reddit OAuth", Category: "site", Host: "oauth.reddit.com"},
		{Name: "Slack App", Category: "site", Host: "app.slack.com"},
		{Name: "Spotify Web", Category: "site", Host: "open.spotify.com"},
		{Name: "Steam", Category: "site", Host: "store.steampowered.com"},
		{Name: "Telegram", Category: "site", Host: "telegram.org"},
		{Name: "Wikipedia", Category: "site", Host: "www.wikipedia.org"},
		{Name: "X", Category: "site", Host: "x.com"},
		{Name: "YouTube API", Category: "site", Host: "youtubei.googleapis.com"},
		{Name: "Zoom API", Category: "site", Host: "api.zoom.us"},
	}
}

func cdnTargets() []Target {
	return []Target{
		{Name: "Akamai Edge", Category: "cdn", Host: "www.akamai.com"},
		{Name: "AWS Static", Category: "cdn", Host: "d1.awsstatic.com"},
		{Name: "CacheFly", Category: "cdn", Host: "cachefly.cachefly.net"},
		{Name: "CDN77 Demo", Category: "cdn", Host: "1906714720.rsc.cdn77.org"},
		{Name: "Cloudflare CDNJS", Category: "cdn", Host: "cdnjs.cloudflare.com"},
		{Name: "Fastly Demo", Category: "cdn", Host: "http-me.fastly.dev"},
		{Name: "Google Fonts Static", Category: "cdn", Host: "fonts.gstatic.com"},
		{Name: "Google Hosted Libraries", Category: "cdn", Host: "ajax.googleapis.com"},
		{Name: "jsDelivr", Category: "cdn", Host: "cdn.jsdelivr.net"},
		{Name: "Microsoft Ajax CDN", Category: "cdn", Host: "ajax.aspnetcdn.com"},
		{Name: "QUANTIL Edge", Category: "cdn", Host: "www.quantil.com"},
		{Name: "Tencent EdgeOne", Category: "cdn", Host: "edgeone.ai"},
		{Name: "UNPKG", Category: "cdn", Host: "unpkg.com"},
		{Name: "Vercel Edge", Category: "cdn", Host: "vercel.com"},
	}
}
